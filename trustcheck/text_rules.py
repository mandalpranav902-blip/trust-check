"""Deterministic text inspection rules covering English, Hindi (Devanagari), and Hinglish."""

from __future__ import annotations

import re

from trustcheck.url_rules import RuleFlag

# Defensive phrases in legitimate bank OTP messages ("Do NOT share this OTP with anyone")
_DEFENSIVE_OTP_RE = re.compile(
    r"\b(?:do\s+not\s+share|don'?t\s+share|never\s+share|never\s+asks?\s+for|"
    r"kisi\s+ke\s+saath\s+share\s+na|mat\s+batao|साझा\s+न\s+करें|किसी\s+को\s+न\s+बताएं)\b",
    re.IGNORECASE,
)


class _PatternRule:
    """Internal definition for a multi-lingual regex rule."""

    def __init__(
        self,
        rule_id: str,
        label: str,
        weight: int,
        patterns: tuple[str, ...],
        requires_no_defensive_otp: bool = False,
    ) -> None:
        self.rule_id = rule_id
        self.label = label
        self.weight = weight
        self.compiled = [re.compile(p, re.IGNORECASE) for p in patterns]
        self.requires_no_defensive_otp = requires_no_defensive_otp


TEXT_RULES: tuple[_PatternRule, ...] = (
    # 1. Urgency & countdown threat language
    _PatternRule(
        rule_id="text_urgency_threat",
        label="Creates artificial urgency or an immediate deadline to force quick action",
        weight=22,
        patterns=(
            r"\b(?:immediately|urgent(?:ly)?|within\s+\d+\s*(?:hours?|hrs?|mins?|minutes?)|"
            r"tonight\s+(?:at\s+)?\d{1,2}(?::\d{2})?\s*(?:pm|am)?|last\s+warning|final\s+notice|"
            r"expire\s+today|suspended\s+today)\b",
            r"\b(?:turant|turanth|abhi\s+ke\s+abhi|aaj\s+raat|jaldi\s+karein|antim\s+chetavani)\b",
            r"(?:तुरंत|अभी\s+अपडेट|आज\s+रात|अंतिम\s+चेतावनी| २४\s*घंटे|24\s*घंटे\s*के\s*अंदर)",
        ),
    ),
    # 2. KYC / PAN / Aadhaar update or suspension lures
    _PatternRule(
        rule_id="text_kyc_pan_aadhaar",
        label="Claims your KYC, PAN, or Aadhaar is expired or requires urgent link verification",
        weight=38,
        patterns=(
            r"\b(?:kyc\s+(?:is\s+)?(?:expired|suspended|incomplete|pending|blocked|update|verification)|"
            r"update\s+(?:your\s+)?(?:kyc|pan\s*card|aadhaar)|"
            r"pan\s*card\s+(?:is\s+)?(?:blocked|suspended|inoperative|expired|not\s+linked)|"
            r"link\s+(?:your\s+)?(?:pan|aadhaar)\s+immediately|"
            r"re-?verify\s+(?:your\s+)?(?:kyc|pan|account))\b",
            r"\b(?:kyc\s+(?:band|rok|update\s+karein|poora\s+karein)|pan\s+card\s+band)\b",
            r"(?:केवाईसी\s+(?:अपडेट|बंद|समाप्त|लंबित)|पैन\s+कार्ड\s+(?:बंद|ब्लॉक|अपडेट)|आधार\s+लिंक\s+करें)",
        ),
    ),
    # 3. Bank account blocked / frozen threat
    _PatternRule(
        rule_id="text_account_blocked",
        label="Threatens that your bank account or netbanking has been blocked or frozen",
        weight=38,
        patterns=(
            r"\b(?:(?:bank\s+|saving\s+)?account\s+(?:has\s+been\s+|will\s+be\s+|is\s+)?"
            r"(?:blocked|suspended|frozen|deactivated|closed|hold)|"
            r"(?:net\s*banking|yono|debit\s+card|credit\s+card)\s+(?:has\s+been\s+|will\s+be\s+)?"
            r"(?:blocked|suspended|deactivated))\b",
            r"\b(?:khata\s+(?:band|block|freeze)|account\s+band\s+ho\s+(?:gaya|jayega))\b",
            r"(?:खाता\s+(?:बंद|ब्लॉक|फ्रीज)|अकाउंट\s+(?:ब्लॉक|बंद\s+हो\s+जाएगा))",
        ),
    ),
    # 4. Electricity disconnection scam
    _PatternRule(
        rule_id="text_electricity_disconnect",
        label="Threatens tonight's electricity disconnection over an unpaid or unupdated bill",
        weight=52,
        patterns=(
            r"\b(?:electricity\s+(?:power\s+|connection\s+|supply\s+)?(?:will\s+be\s+|shall\s+be\s+)?"
            r"(?:disconnected|cut\s+off|stopped)|"
            r"power\s+supply\s+will\s+be\s+disconnected|"
            r"previous\s+month\s+bill\s+was\s+not\s+updated|"
            r"contact\s+electricity\s+(?:officer|board|helpline))\b",
            r"\b(?:bijli\s+(?:connection\s+)?kat\s+(?:jayegi|jayega)|light\s+kat\s+jayegi|"
            r"bijli\s+bill\s+update\s+nahi)\b",
            r"(?:बिजली\s+(?:कनेक्शन|सप्लाई)\s+काट\s+दिया\s+जाएगा|बिजली\s+बिल\s+अपडेट\s+नहीं|बिजली\s+अधिकारी)",
        ),
    ),
    # 5. Lottery, prize, KBC, or expiring reward points lure
    _PatternRule(
        rule_id="text_lottery_prize",
        label="Promises an unclaimed lottery, lucky draw prize, or expiring cash reward points",
        weight=45,
        patterns=(
            r"\b(?:won\s+(?:a\s+)?(?:lottery|prize|lucky\s+draw|cash\s+reward|bumper\s+prize)|"
            r"kbc\s+(?:lucky\s+draw|lottery|winner)|"
            r"reward\s+points?\s+(?:worth\s+|of\s+)?(?:rs\.?|inr|₹)?\s*\d[\d,]*\s*(?:are\s+|is\s+)?expiring|"
            r"redeem\s+(?:your\s+)?(?:reward\s+)?points\s+(?:for\s+cash|now|immediately)|"
            r"congratulations!\s+you\s+have\s+won)\b",
            r"\b(?:lottery\s+jeet(?:a|e)|inaam\s+jeeta|lucky\s+winner\s+चुने)\b",
            r"(?:लॉटरी\s+जीती|इनाम\s+जीता\s+है|रिवॉर्ड\s+पॉइंट्स\s+समाप्त|केबीसी\s+लकी\s+ड्रॉ)",
        ),
    ),
    # 6. Fake job offer, YouTube/Telegram task scam, or upfront registration fee
    _PatternRule(
        rule_id="text_job_task_fee",
        label="Solicits for high-daily-pay tasks or asks for an upfront job registration fee",
        weight=48,
        patterns=(
            r"\b(?:(?:earn|make)\s+(?:rs\.?|inr|₹)?\s*\d[\d,]*\s*(?:to\s+(?:rs\.?|inr|₹)?\s*\d[\d,]*\s*)?"
            r"(?:per\s+day|daily|a\s+day)\s+(?:from\s+home|working\s+part[\s\-]?time)?|"
            r"(?:like|subscribe)\s+(?:youtube\s+videos?|google\s+maps\s+reviews?)\s+and\s+(?:earn|get\s+paid)|"
            r"(?:prepaid|vip|telegram)\s+(?:welfare\s+|merchant\s+)?task|"
            r"(?:pay|deposit|refundable)\s+(?:a\s+)?(?:registration|security|joining|processing|document)\s+fee|"
            r"part[\s\-]?time\s+(?:wfh\s+|online\s+)?job.*?(?:daily\s+payout|whatsapp|telegram))\b",
            r"\b(?:ghar\s+baithe\s+kamaye|part\s+time\s+job.*?rozana\s+kamaye|registration\s+fees?\s+jama)\b",
            r"(?:घर\s+बैठे\s+(?:लाखों\s+|हजारों\s+|रोज़ाना\s+)?कमाएं|पार्ट\s+टाइम\s+जॉब|रजिस्ट्रेशन\s+फीस|टेलीग्राम\s+टास्क)",
        ),
    ),
    # 7. Parcel / customs / FedEx contraband seizure fraud
    _PatternRule(
        rule_id="text_parcel_customs",
        label="Claims a courier parcel in your name was seized by customs or contains illegal items",
        weight=52,
        patterns=(
            r"\b(?:parcel\s+(?:has\s+been\s+|is\s+)?(?:seized|detained|held|intercepted)\s+by\s+customs|"
            r"(?:illegal|prohibited|narcotics|mdma|fake\s+passports?)\s+(?:items?\s+)?(?:found\s+in|inside)\s+(?:your\s+)?parcel|"
            r"(?:fedex|dhl|bluedart|india\s+post)\s+(?:parcel|package)\s+.*?(?:customs|police|cbi|seized|clearance\s+fee)|"
            r"pay\s+customs\s+(?:clearance|duty|penalty)\s+to\s+release)\b",
            r"\b(?:parcel\s+customs?\s+ne\s+(?:pakda|roka)|illegal\s+samaan\s+mila)\b",
            r"(?:पार्सल\s+कस्टम्स\s+द्वारा\s+जब्त|पार्सल\s+में\s+अवैध\s+सामान|कस्टम\s+क्लियरेंस\s+फीस)",
        ),
    ),
    # 8. Active OTP / PIN / CVV / password solicitation
    _PatternRule(
        rule_id="text_otp_pin_request",
        label="Asks you to share an OTP, UPI PIN, ATM PIN, or card CVV",
        weight=58,
        requires_no_defensive_otp=True,
        patterns=(
            r"\b(?:(?:please\s+|kindly\s+)?(?:share|send|reply\s+with|provide|tell|enter|forward|confirm)\s+"
            r"(?:your\s+|the\s+|this\s+)?(?:\d[\s\-]?digit\s+)?(?:otp|one\s+time\s+password|cvv|atm\s+pin|mpin|netbanking\s+password)|"
            r"(?:otp|cvv|mpin)\s+(?:is\s+required\s+to\s+cancel|to\s+our\s+(?:executive|officer|agent|representative)))\b",
            r"\b(?:otp\s+(?:share\s+karein|batao|bataye|bhejein|send\s+karein)|apna\s+pin\s+bataye)\b",
            r"(?:ओटीपी\s+(?:शेयर\s+करें|बताएं|भेजें|दर्ज\s+करें)|अपना\s+(?:पिन|सीवीवी)\s+बताएं)",
        ),
    ),
    # 9. Remote-access application request
    _PatternRule(
        rule_id="text_remote_access",
        label="Instructs you to install a remote screen-sharing app (AnyDesk, TeamViewer, QuickSupport)",
        weight=68,
        patterns=(
            r"\b(?:anydesk|teamviewer|quicksupport|rustdesk|airdroid|ultraviewer|isl\s*light|"
            r"remote\s+support\s+apk|screen\s*share\s+app)\b",
            r"(?:एनीडेस्क|टीमव्यूअर|स्क्रीन\s+शेयर\s+ऐप)",
        ),
    ),
    # 10. Digital arrest / police / CBI / ED / RBI / cybercrime warrant impersonation
    _PatternRule(
        rule_id="text_digital_arrest",
        label="Threatens 'digital arrest', police/CBI/ED interrogation, or money-laundering warrants",
        weight=68,
        patterns=(
            r"\b(?:digital\s+arrest|under\s+house\s+arrest\s+on\s+(?:skype|whatsapp|video\s+call)|"
            r"(?:cbi|enforcement\s+directorate|narcotics\s+control\s+bureau|ncb|mumbai\s+crime\s+branch|"
            r"supreme\s+court|rbi\s+governor)\s+.*?(?:arrest\s+warrant|money\s+laundering|fir\s+registered|"
            r"video\s+interrogation|skype\s+statement|freeze\s+all\s+accounts)|"
            r"non[\s\-]?bailable\s+warrant\s+issued\s+against\s+your\s+aadhaar)\b",
            r"\b(?:digital\s+arrest\s+warrant|cbi\s+officer\s+speaking|giraftari\s+warrant)\b",
            r"(?:डिजिटल\s+अरेस्ट|गिरफ्तारी\s+वारंट|सीबीआई\s+अधिकारी|मनी\s+लॉन्ड्रिंग\s+केस|वीडियो\s+कॉल\s+पूछताछ)",
        ),
    ),
)


def has_defensive_otp_warning(text: str) -> bool:
    """Return True if the message explicitly warns the user NOT to share their OTP/PIN."""
    return bool(_DEFENSIVE_OTP_RE.search(text))


def evaluate_text(text: str) -> list[RuleFlag]:
    """Evaluate raw message text against multi-lingual scam and coercion rules."""
    if not text or not text.strip():
        return []

    flags: list[RuleFlag] = []
    defensive_otp = has_defensive_otp_warning(text)

    for rule in TEXT_RULES:
        if rule.requires_no_defensive_otp and defensive_otp:
            continue

        for regex in rule.compiled:
            match = regex.search(text)
            if match:
                evidence = " ".join(match.group(0).split())
                flags.append(
                    RuleFlag(
                        id=rule.rule_id,
                        label=rule.label,
                        weight=rule.weight,
                        evidence=evidence,
                        category="text",
                    )
                )
                break

    return flags
