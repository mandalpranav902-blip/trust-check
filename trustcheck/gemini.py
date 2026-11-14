"""Gemini LLM enrichment layer with strict 5-second timeout and deterministic fallback.

IMPORTANT:
- The LLM receives the deterministic result as context.
- It may refine `scam_type` and generate a plain-language 2-3 sentence `explanation`.
- It MUST NEVER alter `verdict` or `score`.
- If GEMINI_API_KEY is missing or the call fails/times out, it falls back cleanly
  to the deterministic template explanation with `ai_used=False`.
"""

from __future__ import annotations

import dataclasses
import json
import os
import urllib.error
import urllib.request
from typing import Any

from trustcheck.scoring import AnalysisResult

DEFAULT_GEMINI_MODEL = "gemini-3.8-flash"
TIMEOUT_SECONDS = 5.0

_SYSTEM_INSTRUCTION = (
    "You are TrustCheck, an India-focused security research instrument that explains scam and phishing "
    "signals in calm, plain, direct language. You are given a user-submitted message and the deterministic "
    "rule engine output (verdict, score, and matched evidence flags). "
    "Return ONLY valid JSON with two keys: "
    '"scam_type" (concise classification, e.g. "Electricity Bill Disconnection Scam" or "No Scam Detected") '
    'and "explanation" (2 to 3 clear sentences explaining why the message received its verdict, citing '
    "the concrete evidence matched). Do NOT contradict the deterministic verdict or score."
)


def _is_valid_api_key(api_key: str | None) -> bool:
    """Return True if a non-placeholder Gemini API key is configured."""
    if not api_key:
        return False
    stripped = api_key.strip()
    if not stripped or stripped in {"MY_GEMINI_API_KEY", "your_gemini_api_key_here"}:
        return False
    return True


def _build_prompt(raw_input: str, deterministic: AnalysisResult) -> str:
    """Construct the structured context prompt for Gemini."""
    flags_summary = [
        {
            "id": f.id,
            "category": f.category,
            "reason": f.label,
            "evidence": f.evidence,
            "weight": f.weight,
        }
        for f in deterministic.flags
    ]
    payload = {
        "deterministic_verdict": deterministic.verdict,
        "deterministic_score": deterministic.score,
        "default_scam_type": deterministic.scam_type,
        "matched_flags": flags_summary,
        "submitted_text": raw_input[:2000],
    }
    return json.dumps(payload, ensure_ascii=False)


def _parse_llm_json(raw_text: str) -> tuple[str, str] | None:
    """Parse and validate strict JSON {'scam_type': str, 'explanation': str} from model output."""
    cleaned = raw_text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if len(lines) >= 3:
            cleaned = "\n".join(lines[1:-1]).strip()

    data: Any = json.loads(cleaned)
    if not isinstance(data, dict):
        return None

    scam_type = str(data.get("scam_type") or "").strip()
    explanation = str(data.get("explanation") or "").strip()
    if not scam_type or not explanation:
        return None
    return scam_type, explanation


def _call_via_google_genai_sdk(prompt: str, api_key: str, model_name: str) -> tuple[str, str] | None:
    """Attempt Gemini call via the official `google-genai` Python SDK if installed."""
    from google import genai  # type: ignore[import-not-found]
    from google.genai import types  # type: ignore[import-not-found]

    client = genai.Client(
        api_key=api_key,
        http_options=types.HttpOptions(
            timeout=int(TIMEOUT_SECONDS * 1000),
            headers={"User-Agent": "aistudio-build"},
        ),
    )
    response = client.models.generate_content(
        model=model_name,
        contents=prompt,
        config=types.GenerateContentConfig(
            system_instruction=_SYSTEM_INSTRUCTION,
            response_mime_type="application/json",
        ),
    )
    text = getattr(response, "text", None)
    if not text:
        return None
    return _parse_llm_json(text)


def _call_via_rest(prompt: str, api_key: str, model_name: str) -> tuple[str, str] | None:
    """Stdlib HTTPS fallback to Gemini generateContent endpoint with strict 5-second timeout."""
    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent"
        f"?key={api_key}"
    )
    body = {
        "systemInstruction": {"parts": [{"text": _SYSTEM_INSTRUCTION}]},
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {
            "responseMimeType": "application/json",
        },
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "User-Agent": "aistudio-build",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
        resp_data = json.loads(resp.read().decode("utf-8"))
    candidates = resp_data.get("candidates") or []
    if not candidates:
        return None
    parts = candidates[0].get("content", {}).get("parts") or []
    if not parts or "text" not in parts[0]:
        return None
    return _parse_llm_json(parts[0]["text"])


def enrich_with_gemini(
    raw_input: str,
    deterministic: AnalysisResult,
    api_key: str | None = None,
) -> AnalysisResult:
    """Enrich deterministic AnalysisResult with a Gemini explanation without changing verdict or score."""
    resolved_key = api_key if api_key is not None else os.environ.get("GEMINI_API_KEY")
    if not _is_valid_api_key(resolved_key):
        return deterministic

    assert resolved_key is not None
    model_name = os.environ.get("GEMINI_MODEL", DEFAULT_GEMINI_MODEL).strip() or DEFAULT_GEMINI_MODEL
    prompt = _build_prompt(raw_input, deterministic)

    # Try official google-genai SDK first, then stdlib REST fallback (also trying gemini-4-hydrogen if alias needed)
    models_to_try = [model_name]
    if "gemini-4-hydrogen" not in models_to_try:
        models_to_try.append("gemini-4-hydrogen")

    for candidate_model in models_to_try:
        try:
            try:
                parsed = _call_via_google_genai_sdk(prompt, resolved_key, candidate_model)
            except ImportError:
                parsed = _call_via_rest(prompt, resolved_key, candidate_model)

            if parsed is not None:
                llm_scam_type, llm_explanation = parsed
                # Enforce invariant: verdict and score are NEVER modified by the LLM
                final_scam_type = (
                    "No Scam Detected" if deterministic.verdict == "safe" else llm_scam_type
                )
                return dataclasses.replace(
                    deterministic,
                    scam_type=final_scam_type,
                    explanation=llm_explanation,
                    ai_used=True,
                )
        except (urllib.error.URLError, TimeoutError, ValueError, KeyError, Exception):
            continue

    return deterministic
