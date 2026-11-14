"""Deterministic URL inspection rules for Indian brand impersonation and phishing patterns."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class RuleFlag:
    """Represents a single deterministic detection signal with exact evidence."""

    id: str
    label: str
    weight: int
    evidence: str
    category: str  # "url" | "text" | "upi"


# Curated list of protected Indian brands and their legitimate official registrable domains
INDIAN_BRANDS: dict[str, tuple[str, ...]] = {
    "sbi": ("sbi.co.in", "onlinesbi.sbi", "sbicard.com", "sbimf.com", "yonosbi.com"),
    "onlinesbi": ("onlinesbi.sbi", "sbi.co.in"),
    "yonosbi": ("onlinesbi.sbi", "sbi.co.in", "yonosbi.com"),
    "hdfc": ("hdfcbank.com", "hdfc.com", "hdfclife.com", "hdfcergo.com"),
    "hdfcbank": ("hdfcbank.com", "hdfc.com"),
    "icici": ("icicibank.com", "iciciprulife.com", "icicidirect.com"),
    "icicibank": ("icicibank.com",),
    "axis": ("axisbank.com", "axismf.com"),
    "axisbank": ("axisbank.com",),
    "kotak": ("kotak.com", "kotakbank.com"),
    "pnb": ("pnbindia.in", "netpnb.com"),
    "canarabank": ("canarabank.com",),
    "paytm": ("paytm.com", "paytmbank.com", "paytmmoney.com"),
    "phonepe": ("phonepe.com",),
    "gpay": ("pay.google.com", "google.com"),
    "jio": ("jio.com", "jiocinema.com", "jiomart.com"),
    "airtel": ("airtel.in", "airtel.com"),
    "bsnl": ("bsnl.co.in", "bsnl.in"),
    "irctc": ("irctc.co.in", "irctc.com"),
    "indiapost": ("indiapost.gov.in",),
    "incometax": ("incometax.gov.in", "incometaxindia.gov.in"),
    "uidai": ("uidai.gov.in",),
    "aadhaar": ("uidai.gov.in",),
    "epfo": ("epfindia.gov.in",),
    "parivahan": ("parivahan.gov.in",),
    "echallan": ("parivahan.gov.in",),
    "bescom": ("bescom.karnataka.gov.in", "bescom.org"),
    "mseb": ("mahadiscom.in",),
    "mahadiscom": ("mahadiscom.in",),
    "tneb": ("tangedco.org", "tnebnet.org"),
    "uppcl": ("uppcl.org", "uppclonline.com"),
    "tatapower": ("tatapower.com",),
    "bses": ("bsesdelhi.com",),
    "amazon": ("amazon.in", "amazon.com", "amzn.in", "amzn.to"),
    "flipkart": ("flipkart.com", "fkrt.it"),
    "delhivery": ("delhivery.com",),
    "bluedart": ("bluedart.com",),
}

ALL_OFFICIAL_DOMAINS: frozenset[str] = frozenset(
    domain for domains in INDIAN_BRANDS.values() for domain in domains
)

RISKY_TLDS: frozenset[str] = frozenset(
    {
        "xyz",
        "top",
        "click",
        "buzz",
        "loan",
        "work",
        "vip",
        "icu",
        "tk",
        "ml",
        "cf",
        "ga",
        "gq",
        "online",
        "site",
        "live",
        "shop",
        "rest",
        "sbs",
        "cfd",
        "ink",
        "monster",
        "zip",
        "mov",
    }
)

URL_SHORTENERS: frozenset[str] = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "rb.gy",
        "cutt.ly",
        "is.gd",
        "shorturl.at",
        "tiny.cc",
        "ow.ly",
        "rebrand.ly",
        "v.gd",
        "clck.ru",
        "bitly.com",
    }
)

PHISHING_HYPHEN_PATTERNS: tuple[str, ...] = (
    "-kyc",
    "kyc-",
    "-verify",
    "verify-",
    "-update",
    "update-",
    "-unblock",
    "-block",
    "-pan",
    "pan-",
    "-reward",
    "-refund",
    "-claim",
    "-login",
    "-secure",
    "-helpline",
    "-bill",
)

_IPV4_HOST_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def levenshtein_distance(a: str, b: str) -> int:
    """Compute the Levenshtein edit distance between two strings."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    prev_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr_row = [i]
        for j, cb in enumerate(b, start=1):
            insert_cost = curr_row[j - 1] + 1
            delete_cost = prev_row[j] + 1
            replace_cost = prev_row[j - 1] + (0 if ca == cb else 1)
            curr_row.append(min(insert_cost, delete_cost, replace_cost))
        prev_row = curr_row
    return prev_row[-1]


def _normalize_homoglyphs(label: str) -> str:
    """Replace common numeric/character substitutions used in lookalike domains."""
    normalized = label.lower()
    normalized = normalized.replace("0", "o").replace("1", "i").replace("3", "e").replace("5", "s")
    normalized = normalized.replace("rn", "m").replace("vv", "w")
    return normalized


def _parse_host_and_path(raw_url: str) -> tuple[str, str]:
    """Return lowercase hostname (without port) and path/query from raw URL string."""
    candidate = raw_url.strip()
    if "://" not in candidate:
        candidate = "http://" + candidate
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").lower().rstrip(".")
    path = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")
    return host, path


def _registrable_domain(host: str) -> str:
    """Extract the registrable base domain (handling two-part Indian ccTLDs like .co.in, .gov.in)."""
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return host
    two_part_tlds = {"co.in", "gov.in", "org.in", "net.in", "ac.in", "res.in", "nic.in"}
    tail_two = ".".join(parts[-2:])
    if tail_two in two_part_tlds and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _is_official_domain(host: str, official_domains: tuple[str, ...] | frozenset[str]) -> bool:
    """Check whether host is an exact match or legitimate subdomain of an official domain."""
    for official in official_domains:
        if host == official or host.endswith("." + official):
            return True
    return False


def evaluate_urls(urls: list[str]) -> list[RuleFlag]:
    """Evaluate a list of extracted URLs against deterministic phishing and domain rules."""
    flags: list[RuleFlag] = []

    for raw_url in urls:
        host, path = _parse_host_and_path(raw_url)
        if not host:
            continue

        # Skip further checks if it is a known official domain without APK downloads
        if _is_official_domain(host, ALL_OFFICIAL_DOMAINS):
            continue

        reg_domain = _registrable_domain(host)
        reg_label = reg_domain.split(".")[0] if reg_domain else host
        host_labels = [lbl for lbl in host.split(".") if lbl]
        tld = host_labels[-1] if host_labels else ""

        # 1. Raw IP address host
        if _IPV4_HOST_RE.match(host):
            flags.append(
                RuleFlag(
                    id="url_ip_host",
                    label="URL uses a raw IP address instead of a verified domain name",
                    weight=50,
                    evidence=raw_url,
                    category="url",
                )
            )

        # 2. Punycode / IDN homograph attack
        if "xn--" in host:
            flags.append(
                RuleFlag(
                    id="url_punycode",
                    label="Internationalized (Punycode) domain used to mimic trusted characters",
                    weight=50,
                    evidence=raw_url,
                    category="url",
                )
            )

        # 3. URL Shortener
        if reg_domain in URL_SHORTENERS or host in URL_SHORTENERS:
            flags.append(
                RuleFlag(
                    id="url_shortener",
                    label="Shortened link hides the true destination website",
                    weight=28,
                    evidence=raw_url,
                    category="url",
                )
            )

        # 4. Risky TLD
        if tld in RISKY_TLDS:
            flags.append(
                RuleFlag(
                    id="url_risky_tld",
                    label=f"Domain uses a high-risk top-level extension (.{tld})",
                    weight=30,
                    evidence=raw_url,
                    category="url",
                )
            )

        # 5. Excess subdomains (e.g., sbi.login.verify.account.example.com)
        non_tld_depth = len(host_labels) - (2 if reg_domain.count(".") == 2 else 1)
        if non_tld_depth >= 3:
            flags.append(
                RuleFlag(
                    id="url_excess_subdomains",
                    label="Deceptive multi-level subdomains designed to hide the actual domain owner",
                    weight=32,
                    evidence=raw_url,
                    category="url",
                )
            )

        # 6. Phishing hyphen patterns (-kyc-, -verify-, -update-, etc.)
        matched_hyphen = next(
            (pat for pat in PHISHING_HYPHEN_PATTERNS if pat in host or pat in path.lower()),
            None,
        )
        if matched_hyphen:
            flags.append(
                RuleFlag(
                    id="url_phishing_pattern",
                    label=f"Deceptive '{matched_hyphen}' verification pattern in web address",
                    weight=38,
                    evidence=raw_url,
                    category="url",
                )
            )

        # 7. Direct APK file download link (common in Indian banking/electricity malware scams)
        if path.lower().endswith(".apk") or ".apk?" in path.lower():
            flags.append(
                RuleFlag(
                    id="url_apk_download",
                    label="Link points directly to an Android application (.apk) installer",
                    weight=65,
                    evidence=raw_url,
                    category="url",
                )
            )

        # 8. Brand impersonation & lookalike edit-distance check
        impersonated_brand: str | None = None
        normalized_host_flat = _normalize_homoglyphs(host.replace("-", ""))
        normalized_reg_label = _normalize_homoglyphs(reg_label)

        for brand_key, official_domains in INDIAN_BRANDS.items():
            if _is_official_domain(host, official_domains):
                continue

            # Exact brand substring inside an unofficial domain (e.g. sbi-kyc.in, hdfcbank-update.com)
            if brand_key in host or brand_key in normalized_host_flat:
                impersonated_brand = brand_key.upper()
                break

            # Edit-distance check against registrable label or tokens (for keywords >= 4 chars)
            if len(brand_key) >= 4:
                tokens = [t for t in re.split(r"[\-\.]", host) if len(t) >= 4]
                for token in [reg_label, normalized_reg_label, *tokens]:
                    dist = levenshtein_distance(_normalize_homoglyphs(token), brand_key)
                    max_dist = 2 if len(brand_key) >= 7 else 1
                    if 0 < dist <= max_dist and abs(len(token) - len(brand_key)) <= 2:
                        impersonated_brand = brand_key.upper()
                        break
                if impersonated_brand:
                    break

        # Also check unauthorized .gov.in spoofing like "-gov.in" or "gov-" on non-.gov.in domains
        if not impersonated_brand and not host.endswith(".gov.in") and not host.endswith(".nic.in"):
            if "gov-in" in host or "gov.in" in host or "india-gov" in host:
                impersonated_brand = "GOV.IN"

        if impersonated_brand:
            flags.append(
                RuleFlag(
                    id="url_brand_impersonation",
                    label=f"Lookalike domain impersonating {impersonated_brand} outside its official website",
                    weight=60,
                    evidence=raw_url,
                    category="url",
                )
            )

    return flags
