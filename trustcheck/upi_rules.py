"""Deterministic UPI and VPA inspection rules for collect-request and PIN scams."""

from __future__ import annotations

import re

from trustcheck.url_rules import RuleFlag

# Patterns where a scammer claims a user must enter their UPI PIN to RECEIVE money
_PIN_TO_RECEIVE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:enter|put|input|verify|type)\s+(?:your\s+)?(?:\d[\s\-]?digit\s+)?(?:upi\s+|mpin\s+)?pin\s+"
        r"(?:to\s+)?(?:receive|get|claim|accept|credit)\s+(?:money|cashback|refund|payment|amount|rs|₹|\d)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:to\s+receive|for\s+receiving|to\s+credit)\s+(?:rs\.?|inr|₹|\d|money|refund|cashback).*?"
        r"\b(?:enter|input|verify)\s+(?:your\s+)?(?:upi\s+)?pin\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:paisa|paise|refund|cashback)\s+(?:paane|pane|receive\s+karne|lene)\s+ke\s+liye\s+"
        r"(?:apna\s+)?(?:upi\s+)?pin\s+(?:daalein|dalein|enter\s+karein|batao)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:पैसे|रिफंड|कैशबैक|राशि)\s+(?:पाने|प्राप्त\s+करने|लेने)\s+के\s+लिए\s+(?:अपना\s+)?(?:यूपीआई\s+)?पिन\s+(?:डालें|दर्ज\s+करें)",
        re.IGNORECASE,
    ),
)

# Deceptive collect-request instructions ("Approve collect request to get refund")
_COLLECT_TRICK_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:approve|accept|click\s+pay\s+on)\s+(?:the\s+)?(?:upi\s+)?(?:collect\s+request|payment\s+request)\s+"
        r"(?:to\s+)?(?:receive|get|claim|credit)\s+(?:your\s+)?(?:refund|cashback|money|prize|amount|rs|₹)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:click\s+['\"]?pay['\"]?\s+button\s+to\s+(?:receive|get|credit)|"
        r"collect\s+request\s+accept\s+karein\s+(?:refund|paisa)\s+ke\s+liye)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:कलेक्ट\s+रिक्वेस्ट\s+स्वीकार\s+करें|पे\s+बटन\s+दबाकर\s+पैसे\s+प्राप्त\s+करें)",
        re.IGNORECASE,
    ),
)

# Keywords inside a personal/consumer VPA username that impersonate official desks or brands
_SUSPICIOUS_VPA_PREFIX_KEYWORDS: tuple[str, ...] = (
    "refund",
    "kyc",
    "verify",
    "helpline",
    "support",
    "customercare",
    "care",
    "rbi",
    "sbi",
    "hdfc",
    "icici",
    "axis",
    "paytm",
    "phonepe",
    "gpay",
    "pmcare",
    "pmkisan",
    "lottery",
    "kbc",
    "winner",
    "prize",
    "electricity",
    "uppcl",
    "bescom",
    "mseb",
    "customs",
    "police",
    "cbi",
    "irctc",
    "indiapost",
    "cashback",
)


def evaluate_upi(text: str, upi_ids: list[str]) -> list[RuleFlag]:
    """Evaluate text and extracted UPI IDs for UPI collect and PIN-to-receive fraud."""
    flags: list[RuleFlag] = []

    if text:
        # 1. "Enter UPI PIN to receive money" (UPI PIN is ONLY required when sending money)
        for pattern in _PIN_TO_RECEIVE_PATTERNS:
            match = pattern.search(text)
            if match:
                flags.append(
                    RuleFlag(
                        id="upi_pin_to_receive",
                        label="Claims you must enter your UPI PIN to receive money (PIN is only for sending)",
                        weight=72,
                        evidence=" ".join(match.group(0).split()),
                        category="upi",
                    )
                )
                break

        # 2. Collect-request trick ("Approve collect request / click Pay to receive refund")
        for pattern in _COLLECT_TRICK_PATTERNS:
            match = pattern.search(text)
            if match:
                flags.append(
                    RuleFlag(
                        id="upi_collect_trick",
                        label="Disguises an outgoing UPI collect request as an incoming refund or payout",
                        weight=62,
                        evidence=" ".join(match.group(0).split()),
                        category="upi",
                    )
                )
                break

    # 3. Suspicious VPA handle formats
    for vpa in upi_ids:
        user_part, _, handle_part = vpa.lower().partition("@")
        normalized_user = re.sub(r"[^a-z0-9]", "", user_part)

        matched_kw = next(
            (kw for kw in _SUSPICIOUS_VPA_PREFIX_KEYWORDS if kw in normalized_user),
            None,
        )
        if matched_kw:
            flags.append(
                RuleFlag(
                    id="upi_suspicious_vpa",
                    label=f"UPI ID '{vpa}' uses '{matched_kw}' in the handle to impersonate an official desk",
                    weight=46,
                    evidence=vpa,
                    category="upi",
                )
            )
            continue

        # Flag numeric-heavy fake official handles like "customercare" or long random digits if paired with collect
        if handle_part and re.search(r"(?:refund|kyc|reward|claim|bill)", user_part):
            flags.append(
                RuleFlag(
                    id="upi_suspicious_vpa",
                    label=f"Suspicious UPI ID '{vpa}' formatted as a claim or verification account",
                    weight=42,
                    evidence=vpa,
                    category="upi",
                )
            )

    return flags
