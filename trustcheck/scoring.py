"""Deterministic risk scoring, diminishing returns, verdict thresholds, and fallback explanations."""

from __future__ import annotations

from dataclasses import dataclass

from trustcheck.extract import ExtractedEntities, extract_all
from trustcheck.text_rules import evaluate_text
from trustcheck.upi_rules import evaluate_upi
from trustcheck.url_rules import RuleFlag, evaluate_urls


@dataclass(frozen=True)
class AnalysisResult:
    """Complete result returned by the TrustCheck analysis pipeline."""

    verdict: str  # "safe" | "suspicious" | "scam"
    score: int  # 0..100
    scam_type: str
    flags: list[RuleFlag]
    explanation: str
    actions: list[str]
    ai_used: bool = False


def compute_score(flags: list[RuleFlag], entities: ExtractedEntities) -> int:
    """Combine weighted rule flags with diminishing returns and multi-signal corroboration, capped at 100."""
    if not flags:
        return 0

    sorted_weights = sorted((f.weight for f in flags), reverse=True)
    # Diminishing returns schedule: 1.0, 0.72, 0.52, 0.38, 0.25 ...
    decay_factors = (1.0, 0.72, 0.52, 0.38, 0.25)

    raw_total = 0.0
    for idx, weight in enumerate(sorted_weights):
        factor = decay_factors[idx] if idx < len(decay_factors) else 0.18
        raw_total += weight * factor

    # Multi-vector corroboration boost: e.g., URL flag + Text flag, or Electricity/KYC threat + phone number
    categories = {f.category for f in flags}
    flag_ids = {f.id for f in flags}

    if len(categories) >= 2:
        raw_total += 10.0

    # High-confidence Indian scam combinations
    if "text_electricity_disconnect" in flag_ids and (entities.phone_numbers or entities.urls):
        raw_total = max(raw_total, 76.0)
    if ("text_kyc_pan_aadhaar" in flag_ids or "text_account_blocked" in flag_ids) and entities.urls:
        if any(f.category == "url" for f in flags):
            raw_total = max(raw_total, 78.0)
    if "text_job_task_fee" in flag_ids and (entities.amounts or entities.urls or entities.phone_numbers):
        raw_total = max(raw_total, 72.0)
    if "text_parcel_customs" in flag_ids and (entities.phone_numbers or entities.amounts or entities.urls):
        raw_total = max(raw_total, 74.0)
    if "upi_pin_to_receive" in flag_ids or "upi_collect_trick" in flag_ids:
        raw_total = max(raw_total, 78.0)
    if "text_remote_access" in flag_ids or "text_digital_arrest" in flag_ids:
        raw_total = max(raw_total, 76.0)

    return min(100, max(0, int(round(raw_total))))


def determine_verdict(score: int) -> str:
    """Map numerical score (0-100) to strict verdict threshold: <30 safe, 30-64 suspicious, >=65 scam."""
    if score < 30:
        return "safe"
    if score < 65:
        return "suspicious"
    return "scam"


def classify_scam_type(flags: list[RuleFlag], verdict: str) -> str:
    """Infer a concise, human-readable scam classification from matched rule flags."""
    if not flags or verdict == "safe":
        return "No Scam Detected"

    flag_ids = {f.id for f in flags}

    if "text_digital_arrest" in flag_ids:
        return "Digital Arrest & Law Enforcement Impersonation"
    if "text_remote_access" in flag_ids:
        return "Remote Access App Takeover Scam"
    if "upi_pin_to_receive" in flag_ids or "upi_collect_trick" in flag_ids or "upi_suspicious_vpa" in flag_ids:
        return "UPI Collect & PIN-to-Receive Fraud"
    if "text_electricity_disconnect" in flag_ids:
        return "Electricity Bill Disconnection Scam"
    if "text_parcel_customs" in flag_ids:
        return "Fake Courier & Customs Seizure Scam"
    if "text_job_task_fee" in flag_ids:
        return "Prepaid Task & Fake Job Offer Scam"
    if "text_kyc_pan_aadhaar" in flag_ids or "text_account_blocked" in flag_ids:
        return "Banking KYC / PAN Suspension Phishing"
    if "text_lottery_prize" in flag_ids:
        return "Lottery & Expiring Reward Points Lure"
    if "text_otp_pin_request" in flag_ids:
        return "OTP & Credential Harvesting Attempt"
    if "url_apk_download" in flag_ids:
        return "Malicious APK Installer Distribution"
    if "url_brand_impersonation" in flag_ids:
        return "Brand Impersonation Phishing Link"
    if any(f.category == "url" for f in flags):
        return "Suspicious Link / Unverified Domain"
    return "Suspicious Social Engineering Message"


def build_actions(flags: list[RuleFlag], verdict: str) -> list[str]:
    """Generate concrete, actionable next steps tailored to the verdict and matched signals."""
    if verdict == "safe":
        return [
            "No high-risk scam patterns were matched, but always verify unexpected requests directly through official bank or merchant apps.",
            "Never share your OTP, UPI PIN, or card CVV with anyone over phone, SMS, or WhatsApp.",
        ]

    flag_ids = {f.id for f in flags}
    actions: list[str] = []

    if any(
        fid in flag_ids
        for fid in ("upi_pin_to_receive", "upi_collect_trick", "upi_suspicious_vpa")
    ):
        actions.append(
            "Decline the UPI collect request immediately. Remember: you NEVER need to enter a UPI PIN to receive money."
        )

    if any(f.category == "url" for f in flags):
        actions.append(
            "Do not open the link or enter any login, PAN, Aadhaar, or card details on the page."
        )

    if "url_apk_download" in flag_ids or "text_remote_access" in flag_ids:
        actions.append(
            "Never install .apk files sent via SMS/WhatsApp or screen-sharing apps like AnyDesk or TeamViewer at a caller's request."
        )

    if "text_digital_arrest" in flag_ids or "text_parcel_customs" in flag_ids:
        actions.append(
            "Hang up immediately. Indian police, CBI, ED, and Customs never conduct 'digital arrests' or demand money over Skype/WhatsApp video calls."
        )

    if "text_electricity_disconnect" in flag_ids:
        actions.append(
            "Do not call the mobile number in the message. Check your bill status directly on your state electricity board's official portal or UPI biller."
        )

    if "text_job_task_fee" in flag_ids:
        actions.append(
            "Do not pay any registration deposit or 'prepaid task' amount. Legitimate employers never charge fees to release your earnings."
        )

    if "text_kyc_pan_aadhaar" in flag_ids or "text_account_blocked" in flag_ids:
        actions.append(
            "Open your bank's official mobile app or visit your branch directly to check your KYC status—never use links sent via SMS."
        )

    actions.append(
        "If you have already shared an OTP, PIN, or transferred money, call the National Cyber Crime Helpline at 1930 immediately and file a report at cybercrime.gov.in."
    )

    return actions[:4]


def build_template_explanation(
    verdict: str, score: int, scam_type: str, flags: list[RuleFlag]
) -> str:
    """Generate a clear, 2-3 sentence deterministic explanation when AI is disabled or unavailable."""
    if verdict == "safe":
        if not flags:
            return (
                "This message does not contain known phishing domains, coercive urgency language, or deceptive UPI patterns. "
                "Standard transactional messages and OTP alerts that warn you not to share your code are normal, provided you initiated the action."
            )
        top_reason = flags[0].label.lower()
        return (
            f"This message scored {score}/100 (Safe) with only a minor signal ({top_reason}). "
            "No brand impersonation or credential harvesting patterns were detected, though you should still verify the sender before clicking unfamiliar links."
        )

    top_labels = [f.label.lower() for f in flags[:2]]
    top_evidence = [f"'{f.evidence}'" for f in flags[:2] if f.evidence]
    reasons_str = " and ".join(top_labels)
    evidence_str = ", ".join(top_evidence)

    if verdict == "scam":
        return (
            f"This input matches the pattern of a {scam_type} (risk score {score}/100). "
            f"Our rules flagged {reasons_str} based on matched evidence ({evidence_str}). "
            "Do not click any links, call the listed number, or approve any payment request."
        )

    return (
        f"This message exhibits warning signs consistent with {scam_type} (risk score {score}/100). "
        f"Specifically, it triggered signals for {reasons_str} ({evidence_str}). "
        "Treat this request with caution and verify independently through an official app or website before taking action."
    )


def evaluate_deterministic(text: str) -> AnalysisResult:
    """Run the pure deterministic rule pipeline on raw text and return an AnalysisResult."""
    cleaned_text = (text or "").strip()
    entities = extract_all(cleaned_text)

    raw_flags: list[RuleFlag] = []
    raw_flags.extend(evaluate_urls(entities.urls))
    raw_flags.extend(evaluate_text(cleaned_text))
    raw_flags.extend(evaluate_upi(cleaned_text, entities.upi_ids))

    # Deduplicate flags by rule id, keeping the highest weight instance
    deduped_by_id: dict[str, RuleFlag] = {}
    for flag in raw_flags:
        existing = deduped_by_id.get(flag.id)
        if existing is None or flag.weight > existing.weight:
            deduped_by_id[flag.id] = flag

    sorted_flags = sorted(deduped_by_id.values(), key=lambda f: f.weight, reverse=True)
    score = compute_score(sorted_flags, entities)
    verdict = determine_verdict(score)
    scam_type = classify_scam_type(sorted_flags, verdict)
    actions = build_actions(sorted_flags, verdict)
    explanation = build_template_explanation(verdict, score, scam_type, sorted_flags)

    return AnalysisResult(
        verdict=verdict,
        score=score,
        scam_type=scam_type,
        flags=sorted_flags,
        explanation=explanation,
        actions=actions,
        ai_used=False,
    )
