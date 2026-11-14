/**
 * @license
 * SPDX-License-Identifier: MIT
 */

import { ArrowRight, Eraser } from 'lucide-react';
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { ResultPanel } from './components/ResultPanel';
import { SAMPLE_PRESETS } from './constants/samples';
import { AnalyzeResponse, SamplePreset } from './types';

const MAX_CHARS = 2000;

export default function App() {
  const [inputText, setInputText] = useState<string>(SAMPLE_PRESETS[0].content);
  const [activePresetId, setActivePresetId] = useState<string | null>(SAMPLE_PRESETS[0].id);
  const [inspectedText, setInspectedText] = useState<string>('');
  const [result, setResult] = useState<AnalyzeResponse | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const hasAutoAnalyzed = useRef<boolean>(false);

  const runAnalysis = useCallback(async (textToInspect: string) => {
    const trimmed = textToInspect.trim();
    if (!trimmed) {
      setError('Please paste an SMS, WhatsApp message, URL, or UPI request to inspect.');
      return;
    }
    if (textToInspect.length > MAX_CHARS) {
      setError(`Input exceeds maximum length of ${MAX_CHARS} characters.`);
      return;
    }

    setIsLoading(true);
    setError(null);
    setInspectedText(trimmed);

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ input: trimmed }),
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(
          typeof data?.detail === 'string'
            ? data.detail
            : `Analysis request failed (status ${response.status}).`,
        );
      }

      setResult(data as AnalyzeResponse);
    } catch (err) {
      const message =
        err instanceof Error
          ? err.message
          : 'Unable to reach the inspection engine. Please try again.';
      setError(message);
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Run initial sample automatically on mount so the user sees live evidence immediately
  useEffect(() => {
    if (!hasAutoAnalyzed.current) {
      hasAutoAnalyzed.current = true;
      void runAnalysis(SAMPLE_PRESETS[0].content);
    }
  }, [runAnalysis]);

  const handleSelectPreset = (preset: SamplePreset) => {
    setActivePresetId(preset.id);
    setInputText(preset.content);
    void runAnalysis(preset.content);
  };

  const handleClear = () => {
    setActivePresetId(null);
    setInputText('');
    setResult(null);
    setError(null);
    setInspectedText('');
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    void runAnalysis(inputText);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
      e.preventDefault();
      void runAnalysis(inputText);
    }
  };

  return (
    <div className="min-h-screen bg-[#0b0b0e] text-[#f4f4f6] flex flex-col justify-between">
      {/* Top Bar Contract: 3 zones separated by gap-8 */}
      <header className="border-b border-[rgba(255,255,255,0.10)] bg-[#0b0b0e]">
        <div className="mx-auto flex max-w-6xl items-center justify-between gap-8 px-5 py-4 sm:px-8">
          {/* Zone 1: Single wordmark */}
          <a
            href="#top"
            className="font-display type-20 font-bold tracking-tight text-[#f4f4f6] whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#ff4a1f]"
          >
            TrustCheck
          </a>

          {/* Zone 2: Concise single-line navigation links */}
          <nav
            aria-label="Primary navigation"
            className="hidden md:flex items-center gap-6 type-14 text-[#8a8a93]"
          >
            <a
              href="#inspector"
              className="hover:text-[#f4f4f6] hover:underline underline-offset-4 instrument-transition whitespace-nowrap shrink-0"
            >
              Inspector
            </a>
            <a
              href="#result-zone"
              className="hover:text-[#f4f4f6] hover:underline underline-offset-4 instrument-transition whitespace-nowrap shrink-0"
            >
              Evidence Matrix
            </a>
            <a
              href="#how-it-works"
              className="hover:text-[#f4f4f6] hover:underline underline-offset-4 instrument-transition whitespace-nowrap shrink-0"
            >
              How It Works
            </a>
            <a
              href="https://cybercrime.gov.in"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-[#f4f4f6] hover:underline underline-offset-4 instrument-transition whitespace-nowrap shrink-0"
            >
              Cybercrime Portal
            </a>
          </nav>

          {/* Zone 3: 1 primary action */}
          <div className="flex items-center shrink-0">
            <a
              href="tel:1930"
              className="rounded-[6px] border border-[rgba(255,255,255,0.10)] px-3.5 py-1.5 type-12 font-mono font-medium text-[#f4f4f6] hover:border-[#f4f4f6] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#ff4a1f] instrument-transition whitespace-nowrap shrink-0"
            >
              Helpline 1930
            </a>
          </div>
        </div>
      </header>

      {/* Main Workspace */}
      <main id="top" className="mx-auto w-full max-w-6xl flex-1 px-5 py-10 sm:px-8 md:py-14">
        {/* ZONE 1: Hero / Input */}
        <section id="inspector" aria-labelledby="hero-heading">
          <div className="max-w-3xl">
            <p className="type-12 font-mono tracking-wider text-[#8a8a93] uppercase">
              India Scam &amp; Phishing Research Instrument · Nazar rakho.
            </p>
            <h1
              id="hero-heading"
              className="font-display type-56 mt-2 font-bold tracking-tight text-[#f4f4f6] [text-wrap:balance]"
            >
              See through the scam.
            </h1>
            <p className="type-16 mt-3 max-w-2xl text-[#8a8a93]">
              Paste any suspicious SMS, WhatsApp forward, link, or UPI payment request. TrustCheck extracts domains, VPAs, and English/Hindi/Hinglish threat patterns in memory to show you the exact evidence.
            </p>
          </div>

          {/* Example Sample Presets (4 interactive filter buttons) */}
          <div className="mt-7">
            <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Load example message">
              <span className="type-12 mr-1 font-mono text-[#8a8a93] uppercase">
                Test presets:
              </span>
              {SAMPLE_PRESETS.map((preset) => {
                const isSelected = activePresetId === preset.id;
                return (
                  <button
                    key={preset.id}
                    type="button"
                    onClick={() => handleSelectPreset(preset)}
                    className={`rounded-[6px] border px-3 py-1.5 type-14 font-medium whitespace-nowrap shrink-0 cursor-pointer instrument-transition focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#ff4a1f] ${
                      isSelected
                        ? 'border-[#ff4a1f] bg-[#ff4a1f]/15 text-[#f4f4f6]'
                        : 'border-[rgba(255,255,255,0.10)] bg-transparent text-[#8a8a93] hover:border-[rgba(255,255,255,0.28)] hover:text-[#f4f4f6]'
                    }`}
                  >
                    {preset.label}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Input Form */}
          <form onSubmit={handleSubmit} className="mt-4">
            <div className="rounded-[8px] border border-[rgba(255,255,255,0.10)] bg-[#111116] p-4 focus-within:border-[#f4f4f6] instrument-transition">
              <label htmlFor="scam-input-textarea" className="sr-only">
                Paste suspicious message, URL, or UPI request
              </label>
              <textarea
                id="scam-input-textarea"
                rows={4}
                maxLength={MAX_CHARS}
                value={inputText}
                onChange={(e) => {
                  setInputText(e.target.value);
                  if (activePresetId) setActivePresetId(null);
                }}
                onKeyDown={handleKeyDown}
                placeholder="Paste SMS, WhatsApp forward, URL (e.g., https://sbi-kyc.xyz), or UPI collect request (English, हिन्दी, or Hinglish)..."
                className="w-full resize-y bg-transparent font-mono type-16 text-[#f4f4f6] placeholder-[#8a8a93]/60 focus:outline-none"
              />

              <div className="mt-3 flex flex-wrap items-center justify-between gap-4 border-t border-[rgba(255,255,255,0.10)] pt-3">
                <div className="flex items-center gap-3 type-12 font-mono text-[#8a8a93] tabular-nums">
                  <span>
                    {inputText.length} / {MAX_CHARS} chars
                  </span>
                  <span aria-hidden="true">·</span>
                  <span className="hidden sm:inline">Press Ctrl+Enter to inspect</span>
                </div>

                <div className="flex items-center gap-3">
                  {inputText.length > 0 && (
                    <button
                      type="button"
                      onClick={handleClear}
                      className="inline-flex items-center gap-1.5 rounded-[6px] border border-[rgba(255,255,255,0.10)] px-3 py-2 type-14 font-medium text-[#8a8a93] hover:border-[rgba(255,255,255,0.25)] hover:text-[#f4f4f6] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#ff4a1f] instrument-transition whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      <Eraser className="h-4 w-4" aria-hidden="true" />
                      Clear
                    </button>
                  )}

                  <button
                    type="submit"
                    disabled={isLoading || !inputText.trim()}
                    className="inline-flex items-center gap-2 rounded-[6px] bg-[#ff4a1f] px-5 py-2 type-14 font-semibold text-white hover:bg-[#e03e16] disabled:opacity-40 disabled:pointer-events-none focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#ff4a1f] instrument-transition whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <span>{isLoading ? 'Analyzing...' : 'Analyze'}</span>
                    <ArrowRight className="h-4 w-4" aria-hidden="true" />
                  </button>
                </div>
              </div>
            </div>
          </form>
        </section>

        {/* ZONE 2: Result (Evidence -> Interpretation -> Verdict) */}
        <div id="result-zone" className="mt-10">
          <ResultPanel
            inspectedText={inspectedText}
            result={result}
            isLoading={isLoading}
            error={error}
            onRetry={() => void runAnalysis(inputText)}
          />
        </div>
      </main>

      {/* ZONE 3: Footer (How it works in 3 steps, privacy guarantee, GitHub link) */}
      <footer
        id="how-it-works"
        className="mt-16 border-t border-[rgba(255,255,255,0.10)] bg-[#0b0b0e] py-12"
      >
        <div className="mx-auto max-w-6xl px-5 sm:px-8">
          <div className="mb-8">
            <p className="type-12 font-mono text-[#8a8a93] uppercase">
              Instrument Architecture · Deterministic First, LLM Second
            </p>
            <h2 className="font-display type-20 mt-1 font-semibold text-[#f4f4f6]">
              How TrustCheck works in three steps
            </h2>
          </div>

          <div className="grid grid-cols-1 gap-6 border-b border-[rgba(255,255,255,0.10)] pb-10 md:grid-cols-3">
            <div className="rounded-[8px] border border-[rgba(255,255,255,0.10)] p-5">
              <span className="font-mono type-12 font-semibold text-[#ff4a1f] tabular-nums">
                01. EXTRACT
              </span>
              <h3 className="font-display type-16 mt-1.5 font-semibold text-[#f4f4f6]">
                Parse URLs, VPAs &amp; Entities
              </h3>
              <p className="type-14 mt-1.5 text-[#8a8a93]">
                Pulls explicit links, bare SMS shortlinks, Indian UPI IDs (VPAs), phone numbers, and ₹/Rs amounts from raw messages.
              </p>
            </div>

            <div className="rounded-[8px] border border-[rgba(255,255,255,0.10)] p-5">
              <span className="font-mono type-12 font-semibold text-[#ff4a1f] tabular-nums">
                02. SCORE
              </span>
              <h3 className="font-display type-16 mt-1.5 font-semibold text-[#f4f4f6]">
                Deterministic Rule Engine
              </h3>
              <p className="type-14 mt-1.5 text-[#8a8a93]">
                Evaluates brand lookalikes via Levenshtein edit distance, UPI PIN-to-receive fraud, and English/Hindi/Hinglish threat signals.
              </p>
            </div>

            <div className="rounded-[8px] border border-[rgba(255,255,255,0.10)] p-5">
              <span className="font-mono type-12 font-semibold text-[#ff4a1f] tabular-nums">
                03. EXPLAIN
              </span>
              <h3 className="font-display type-16 mt-1.5 font-semibold text-[#f4f4f6]">
                Plain-Language Synthesis
              </h3>
              <p className="type-14 mt-1.5 text-[#8a8a93]">
                Translates matched flags into a calm 2–3 sentence explanation without ever overriding the deterministic score or verdict.
              </p>
            </div>
          </div>

          <div className="mt-6 flex flex-col items-start justify-between gap-4 type-12 text-[#8a8a93] sm:flex-row sm:items-center">
            <p>
              <strong className="font-medium text-[#f4f4f6]">Privacy guarantee:</strong> Analysed in memory, never stored. User inputs are never logged to disk or external telemetry.
            </p>
            <div className="flex items-center gap-4">
              <span>MIT License</span>
              <span aria-hidden="true">·</span>
              <a
                href="https://github.com/trustcheck-in/trustcheck"
                target="_blank"
                rel="noopener noreferrer"
                className="text-[#f4f4f6] hover:underline underline-offset-4"
              >
                GitHub Repository
              </a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
