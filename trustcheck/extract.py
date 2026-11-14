"""Entity extraction utilities for URLs, UPI IDs (VPAs), phone numbers, and INR amounts."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Known Indian UPI PSP suffixes and bank handles to distinguish VPAs from regular emails
UPI_HANDLES: frozenset[str] = frozenset(
    {
        "ybl",
        "ibl",
        "axl",
        "okaxis",
        "okhdfcbank",
        "oksbi",
        "okicici",
        "paytm",
        "ptyes",
        "ptaxis",
        "pthdfc",
        "ptsbi",
        "apl",
        "rapl",
        "upi",
        "sbi",
        "hdfcbank",
        "icici",
        "axisbank",
        "kotak",
        "barodampay",
        "mahb",
        "fbl",
        "indus",
        "pnb",
        "cnrb",
        "unionbank",
        "ikwik",
        "jio",
        "freecharge",
        "sliceaxis",
        "naviaxis",
        "superyes",
        "waaxis",
        "wahdfcbank",
        "wasbi",
        "waicici",
    }
)

COMMON_EMAIL_DOMAINS: frozenset[str] = frozenset(
    {
        "gmail.com",
        "yahoo.com",
        "yahoo.co.in",
        "outlook.com",
        "hotmail.com",
        "icloud.com",
        "rediffmail.com",
        "proton.me",
        "protonmail.com",
    }
)

# Regex patterns
_EXPLICIT_URL_RE = re.compile(
    r"\b(?:https?://)[a-zA-Z0-9\-\._~:/\?#\[\]@!\$&'\(\)\*\+,;=%]+",
    re.IGNORECASE,
)

# Bare domains / shortlinks in SMS without scheme (e.g., bit.ly/3xYz, sbi-kyc.xyz/login)
_BARE_URL_RE = re.compile(
    r"(?<![@\w/\.])\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:in|co\.in|org\.in|gov\.in|net\.in|ac\.in|com|org|net|info|biz|xyz|top|click|buzz|"
    r"loan|work|vip|icu|tk|ml|cf|ga|gq|online|site|live|shop|rest|sbs|cfd|ink|ly|gy|cc|gd|at|co|me|io|app|apk)"
    r"(?:/[^\s<>\"'\)\],;]*)?",
    re.IGNORECASE,
)

_VPA_RE = re.compile(
    r"\b([a-zA-Z0-9][a-zA-Z0-9\.\-_]{1,63})@([a-zA-Z0-9][a-zA-Z0-9\.\-]{1,31})\b"
)

_PHONE_RE = re.compile(
    r"(?:(?:\+|00)?91[\s\-]?)?(?:\b0)?([6-9]\d{4}[\s\-]?\d{5}\b|\b1800[\s\-]?\d{3}[\s\-]?\d{3,4}\b)"
)

_AMOUNT_RE = re.compile(
    r"(?:(?:₹|Rs\.?|INR)\s*\d[\d,]*(?:\.\d{1,2})?|\b\d[\d,]*(?:\.\d{1,2})?\s*(?:₹|Rs\.?|INR|रुपये|रुपए|rupees)\b)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ExtractedEntities:
    """Container for structured entities pulled from raw message input."""

    urls: list[str] = field(default_factory=list)
    upi_ids: list[str] = field(default_factory=list)
    phone_numbers: list[str] = field(default_factory=list)
    amounts: list[str] = field(default_factory=list)


def _clean_trailing_punctuation(token: str) -> str:
    """Strip sentence punctuation that commonly trails pasted URLs."""
    return token.rstrip(".,;:!?)>\"']")


def extract_upi_ids(text: str) -> list[str]:
    """Extract Indian UPI Virtual Payment Addresses (VPAs) from text."""
    if not text:
        return []

    found: list[str] = []
    seen: set[str] = set()
    lower_text = text.lower()
    has_upi_context = any(
        kw in lower_text for kw in ("upi", "vpa", "paytm", "phonepe", "gpay", "collect", "bhim")
    )

    for match in _VPA_RE.finditer(text):
        full_match = _clean_trailing_punctuation(match.group(0))
        user_part, handle_part = full_match.split("@", 1)
        handle_lower = handle_part.lower()

        if handle_lower in COMMON_EMAIL_DOMAINS:
            continue

        # A valid VPA handle typically has no dots (e.g., @ybl, @okaxis)
        if "." not in handle_lower:
            if handle_lower in UPI_HANDLES or has_upi_context or len(handle_lower) <= 12:
                key = full_match.lower()
                if key not in seen:
                    seen.add(key)
                    found.append(full_match)
        elif user_part and False:  # Keep strict against dotted email domains
            pass

    return found


def extract_urls(text: str) -> list[str]:
    """Extract explicit HTTP(S) URLs and bare domain links from text."""
    if not text:
        return []

    urls: list[str] = []
    seen: set[str] = set()

    # 1. Explicit http:// or https:// URLs
    for match in _EXPLICIT_URL_RE.finditer(text):
        cleaned = _clean_trailing_punctuation(match.group(0))
        key = cleaned.lower()
        if key not in seen:
            seen.add(key)
            urls.append(cleaned)

    # 2. Bare domains or shortener URLs not already covered by explicit URLs
    for match in _BARE_URL_RE.finditer(text):
        start, end = match.span()
        # Skip if preceded by '://' or '@'
        prefix = text[max(0, start - 3) : start]
        if "://" in prefix or "@" in prefix:
            continue
        # Skip if followed immediately by '@' (part of an email/VPA user)
        if end < len(text) and text[end] == "@":
            continue

        cleaned = _clean_trailing_punctuation(match.group(0))
        # Avoid matching things like "Rs.500" or "Mr.Sharma"
        if re.match(r"^(?:rs|inr|mr|mrs|dr|st|no)\.", cleaned, re.IGNORECASE):
            continue

        key = cleaned.lower()
        if any(key in existing or existing.endswith("://" + key) for existing in seen):
            continue

        seen.add(key)
        urls.append(cleaned)

    return urls


def extract_phone_numbers(text: str) -> list[str]:
    """Extract Indian mobile and toll-free phone numbers from text."""
    if not text:
        return []

    numbers: list[str] = []
    seen: set[str] = set()

    for match in _PHONE_RE.finditer(text):
        raw = match.group(0).strip()
        digits_only = re.sub(r"\D", "", raw)
        if digits_only not in seen:
            seen.add(digits_only)
            numbers.append(raw)

    return numbers


def extract_amounts(text: str) -> list[str]:
    """Extract INR currency amounts (₹, Rs., INR, रुपये) from text."""
    if not text:
        return []

    amounts: list[str] = []
    seen: set[str] = set()

    for match in _AMOUNT_RE.finditer(text):
        raw = " ".join(match.group(0).split())
        key = raw.lower()
        if key not in seen:
            seen.add(key)
            amounts.append(raw)

    return amounts


def extract_all(text: str) -> ExtractedEntities:
    """Extract all supported entities (URLs, UPI IDs, phone numbers, amounts) from text."""
    return ExtractedEntities(
        urls=extract_urls(text),
        upi_ids=extract_upi_ids(text),
        phone_numbers=extract_phone_numbers(text),
        amounts=extract_amounts(text),
    )
