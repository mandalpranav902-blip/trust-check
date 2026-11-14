"""TrustCheck: India-focused deterministic + LLM scam and phishing detection package."""

from __future__ import annotations

from trustcheck.extract import (
    ExtractedEntities,
    extract_all,
    extract_amounts,
    extract_phone_numbers,
    extract_upi_ids,
    extract_urls,
)
from trustcheck.gemini import enrich_with_gemini
from trustcheck.scoring import AnalysisResult, evaluate_deterministic
from trustcheck.text_rules import evaluate_text
from trustcheck.upi_rules import evaluate_upi
from trustcheck.url_rules import RuleFlag, evaluate_urls


def analyze_message(text: str, use_ai: bool = True) -> AnalysisResult:
    """Run deterministic inspection first, then optionally enrich with Gemini explanation."""
    deterministic = evaluate_deterministic(text)
    if not use_ai:
        return deterministic
    return enrich_with_gemini(text, deterministic)


__all__ = [
    "AnalysisResult",
    "ExtractedEntities",
    "RuleFlag",
    "analyze_message",
    "enrich_with_gemini",
    "evaluate_deterministic",
    "evaluate_text",
    "evaluate_upi",
    "evaluate_urls",
    "extract_all",
    "extract_amounts",
    "extract_phone_numbers",
    "extract_upi_ids",
    "extract_urls",
]
