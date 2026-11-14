import { GoogleGenAI, Type } from '@google/genai';
import { spawn, type ChildProcess } from 'child_process';
import 'dotenv/config';
import express from 'express';
import http from 'http';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT) || 3000;
const PYTHON_API_PORT = Number(process.env.API_PORT) || 8000;

let pythonProcess: ChildProcess | null = null;

function startPythonBackend(): void {
  if (pythonProcess) return;
  pythonProcess = spawn('python3', [path.join(__dirname, 'api', 'index.py')], {
    env: { ...process.env, API_PORT: String(PYTHON_API_PORT) },
    stdio: 'ignore',
  });
  pythonProcess.on('exit', () => {
    pythonProcess = null;
  });
}

function forwardToPython(
  method: string,
  reqPath: string,
  bodyObj?: unknown,
): Promise<{ status: number; data: Record<string, unknown> }> {
  return new Promise((resolve, reject) => {
    const payloadStr = bodyObj !== undefined ? JSON.stringify(bodyObj) : '';
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port: PYTHON_API_PORT,
        path: reqPath,
        method,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payloadStr),
        },
        timeout: 6500,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf-8');
          try {
            const parsed = JSON.parse(raw) as Record<string, unknown>;
            resolve({ status: res.statusCode || 200, data: parsed });
          } catch {
            reject(new Error('Invalid JSON from Python backend'));
          }
        });
      },
    );

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy(new Error('Python backend timeout'));
    });

    if (payloadStr) {
      req.write(payloadStr);
    }
    req.end();
  });
}

function runPythonCliFallback(inputText: string): Promise<{ status: number; data: Record<string, unknown> }> {
  return new Promise((resolve, reject) => {
    const pyScript = `
import json, sys
from api.index import _validate_and_analyze
payload = json.loads(sys.stdin.read())
status, result = _validate_and_analyze(payload)
print(json.dumps({"status": status, "data": result}, ensure_ascii=False))
`;
    const child = spawn('python3', ['-c', pyScript], {
      cwd: __dirname,
      env: process.env,
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk: Buffer) => {
      stdout += chunk.toString('utf-8');
    });
    child.stderr.on('data', (chunk: Buffer) => {
      stderr += chunk.toString('utf-8');
    });
    child.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(stderr || 'Python execution failed'));
        return;
      }
      try {
        const parsed = JSON.parse(stdout.trim()) as {
          status: number;
          data: Record<string, unknown>;
        };
        resolve(parsed);
      } catch (err) {
        reject(err);
      }
    });
    child.stdin.write(JSON.stringify({ input: inputText }));
    child.stdin.end();
  });
}

async function maybeEnrichWithSdk(
  rawInput: string,
  resultData: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  if (resultData.ai_used === true) {
    return resultData;
  }

  const apiKey = process.env.GEMINI_API_KEY?.trim();
  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY' || apiKey === 'your_gemini_api_key_here') {
    return resultData;
  }

  try {
    const ai = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);

    try {
      const response = await ai.models.generateContent({
        model: 'gemini-4-hydrogen',
        contents: JSON.stringify({
          deterministic_verdict: resultData.verdict,
          deterministic_score: resultData.score,
          default_scam_type: resultData.scam_type,
          matched_flags: resultData.flags,
          submitted_text: rawInput.slice(0, 2000),
        }),
        config: {
          systemInstruction:
            'You are TrustCheck, an India-focused security research instrument that explains scam and phishing signals in calm, plain, direct language. You are given a user-submitted message and the deterministic rule engine output (verdict, score, and matched evidence flags). Return ONLY valid JSON with two keys: "scam_type" (concise classification) and "explanation" (2 to 3 clear sentences explaining why the message received its verdict, citing the concrete matched evidence). Never contradict the deterministic verdict or score.',
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              scam_type: {
                type: Type.STRING,
                description: 'Concise scam classification label.',
              },
              explanation: {
                type: Type.STRING,
                description: '2-3 sentence plain-language explanation referencing matched evidence.',
              },
            },
            required: ['scam_type', 'explanation'],
          },
          abortSignal: controller.signal,
        },
      });

      const text = response.text?.trim();
      if (text) {
        const parsed = JSON.parse(text) as { scam_type?: string; explanation?: string };
        if (parsed.scam_type && parsed.explanation) {
          return {
            ...resultData,
            scam_type:
              resultData.verdict === 'safe' ? 'No Scam Detected' : parsed.scam_type.trim(),
            explanation: parsed.explanation.trim(),
            ai_used: true,
          };
        }
      }
    } finally {
      clearTimeout(timer);
    }
  } catch {
    // Graceful fallback to deterministic template explanation
  }

  return resultData;
}

async function startServer() {
  startPythonBackend();

  const app = express();
  app.use(express.json({ limit: '64kb' }));

  app.get('/api/health', async (_req, res) => {
    try {
      const pyRes = await forwardToPython('GET', '/api/health');
      res.status(pyRes.status).json(pyRes.data);
    } catch {
      res.status(200).json({ status: 'ok' });
    }
  });

  app.post('/api/analyze', async (req, res) => {
    const rawInput = typeof req.body?.input === 'string' ? req.body.input : null;
    if (rawInput === null || !rawInput.trim()) {
      res.status(422).json({ detail: 'Input text cannot be empty.' });
      return;
    }
    if (rawInput.length > 2000) {
      res.status(422).json({ detail: 'Input exceeds maximum allowed length of 2000 characters.' });
      return;
    }

    try {
      let pyRes: { status: number; data: Record<string, unknown> };
      try {
        pyRes = await forwardToPython('POST', '/api/analyze', { input: rawInput });
      } catch {
        startPythonBackend();
        pyRes = await runPythonCliFallback(rawInput);
      }

      if (pyRes.status !== 200) {
        res.status(pyRes.status).json(pyRes.data);
        return;
      }

      const finalData = await maybeEnrichWithSdk(rawInput, pyRes.data);
      res.status(200).json(finalData);
    } catch {
      res.status(500).json({ detail: 'Analysis engine encountered an unexpected error.' });
    }
  });

  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    // Do not log user inputs; server ready
  });
}

startServer();
