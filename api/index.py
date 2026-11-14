"""FastAPI entry point for Vercel (/api/index.py).

GET  /api/health  -> {"status": "ok"}
POST /api/analyze -> verdict, score, flags, explanation, actions
User input is analysed in memory and never logged or stored.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Literal


from fastapi import FastAPI
from pydantic import BaseModel, Field, field_validator
from fastapi import FastAPI, HTTPException

_ROOT_DIR = Path(__file__).resolve().parent.parent
if str(_ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(_ROOT_DIR))

try:
    from dotenv import load_dotenv
except ImportError:  # not needed on Vercel, where env vars are injected
    load_dotenv = None

from trustcheck import analyze_message  # noqa: E402

MAX_INPUT_LENGTH = 2000

def _validate_and_analyze(payload: Any) -> tuple[int, dict[str, Any]]:
    """Validate a JSON payload and run the TrustCheck pipeline in memory."""
    if not isinstance(payload, dict):
        return 422, {"detail": "Request body must be a JSON object."}

    raw_input = payload.get("input")
    if not isinstance(raw_input, str):
        return 422, {"detail": "Field 'input' is required and must be a string."}

    stripped = raw_input.strip()
    if not stripped:
        return 422, {"detail": "Input text cannot be empty."}

    if len(raw_input) > MAX_INPUT_LENGTH:
        return 422, {
            "detail": f"Input exceeds maximum allowed length of {MAX_INPUT_LENGTH} characters."
        }

    result = analyze_message(stripped, use_ai=True)
    return 200, {
        "verdict": result.verdict,
        "score": result.score,
        "scam_type": result.scam_type,
        "flags": [
            {
                "id": f.id,
                "label": f.label,
                "weight": f.weight,
                "evidence": f.evidence,
                "category": f.category,
            }
            for f in result.flags
        ],
        "explanation": result.explanation,
        "actions": result.actions,
        "ai_used": result.ai_used,
    }


class AnalyzeRequest(BaseModel):
    """Request body for POST /api/analyze."""

    input: str = Field(..., min_length=1, max_length=MAX_INPUT_LENGTH)

    @field_validator("input")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Input text cannot be blank.")
        return value


class FlagModel(BaseModel):
    id: str
    label: str
    weight: int
    evidence: str
    category: Literal["url", "text", "upi"]


class AnalyzeResponse(BaseModel):
    verdict: Literal["safe", "suspicious", "scam"]
    score: int = Field(..., ge=0, le=100)
    scam_type: str
    flags: list[FlagModel]
    explanation: str
    actions: list[str]
    ai_used: bool


app = FastAPI(title="TrustCheck API", version="1.0.0", docs_url=None, redoc_url=None)


@app.get("/api/health")
async def health() -> dict[str, str]:
    """Health check."""
    return {"status": "ok"}


@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze(body: AnalyzeRequest) -> dict[str, Any]:
    """Analyse submitted text in memory."""
    status_code, response = _validate_and_analyze({"input": body.input})
    if status_code != 200:
        raise HTTPException(status_code=status_code, detail=response.get("detail"))
    return response