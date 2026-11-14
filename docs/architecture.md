# TrustCheck System Architecture

## 1. Architectural Principles

1. **Deterministic Authority**: Every numerical risk score (`0–100`) and semantic verdict (`safe`, `suspicious`, `scam`) is computed deterministically by pure Python functions in `/trustcheck`.
2. **Evidence Traceability**: No rule may add points to the risk score without returning the exact matched substring (`evidence`) and rule identifier (`id`). The frontend uses these exact substrings to highlight matches inline inside the user's pasted text.
3. **Stateless, Zero-Retention Privacy**: The API processes strings up to `2000` characters in memory and never logs or persists user input.
4. **Graceful LLM Degradation**: The Gemini enrichment layer (`trustcheck/gemini.py`) has a strict 5-second timeout and cannot modify `verdict` or `score`. When `GEMINI_API_KEY` is missing or unreachable, the engine returns deterministic template explanations with `ai_used: false`.

---

## 2. Backend Request Lifecycle (`POST /api/analyze`)

1. **Input Validation (`api/index.py`)**:
   - Validates that `input` is a non-empty string with `1 <= len(input) <= 2000`.
   - Rejects invalid payloads with HTTP `422`.
2. **Entity Extraction (`trustcheck/extract.py`)**:
   - `extract_urls`: Captures both `http(s)://` URLs and bare domains/shortlinks common in Indian SMS messages (`bit.ly/...`, `sbi-kyc.xyz/login`), while excluding UPI VPAs and currency abbreviations (`Rs.500`).
   - `extract_upi_ids`: Identifies Virtual Payment Addresses (`user@handle`) matching Indian PSP handles (`@ybl`, `@okaxis`, `@oksbi`, `@paytm`, `@ibl`, etc.) while ignoring standard email domains (`@gmail.com`).
   - `extract_phone_numbers`: Extracts 10-digit Indian mobile numbers (`+91`, `0`, or bare `[6-9]\d{9}`) and `1800` toll-free numbers.
   - `extract_amounts`: Extracts `₹`, `Rs.`, `INR`, and `रुपये` currency figures.
3. **Rule Evaluation (`url_rules.py`, `text_rules.py`, `upi_rules.py`)**:
   - Each module returns a list of `RuleFlag(id, label, weight, evidence, category)`.
   - Flags are deduplicated by `id` (retaining the highest weight match) and sorted by `weight` descending.
4. **Diminishing-Returns Scoring (`trustcheck/scoring.py`)**:
   - Sorted flag weights $w_0 \ge w_1 \ge \dots \ge w_{n-1}$ are combined using decay multipliers $(1.0, 0.72, 0.52, 0.38, 0.25, 0.18\dots)$.
   - Multi-category corroboration (e.g., a URL flag combined with a coercive text flag, or an electricity disconnection threat paired with an unverified mobile number) ensures real-world Indian scam templates cross the `>= 65` (`scam`) threshold reliably while keeping single weak signals in `safe` (`< 30`) or `suspicious` (`30–64`).
5. **Gemini Synthesis (`trustcheck/gemini.py`)**:
   - Sends the deterministic verdict, score, matched flags, and raw text to Gemini (`gemini-3.8-flash`) with `response_mime_type="application/json"`.
   - Enforces a 5.0-second timeout.
   - Replaces only `scam_type` (when verdict is not `safe`) and `explanation`, setting `ai_used = True`.

---

## 3. Frontend Architecture (`/src`)

- **`App.tsx`**: Manages single-page state across the three zones (Hero/Input, Result Panel, and Footer), handles keyboard shortcuts (`Ctrl/Cmd + Enter`), and provides 4 one-click Indian test presets.
- **`DotMatrixMeter.tsx`**: Renders the `10 × 10` (`100`-dot) risk grid using CSS Grid, tabular numerals (`Bricolage Grotesque`), and staggered transition delays that respect `prefers-reduced-motion: reduce`.
- **`HighlightedEvidenceText.tsx`**: Performs non-overlapping substring segmentation over the original message so every `flag.evidence` span is highlighted inline and synchronized on hover with the grouped flag cards.
- **`ResultPanel.tsx`**: Implements the *Evidence → Interpretation → Verdict* hierarchy, grouped category flags, rules-only fallback notice, actionable next steps, and direct links to `cybercrime.gov.in` and the `1930` helpline.
