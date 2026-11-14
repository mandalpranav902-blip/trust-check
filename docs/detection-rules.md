# TrustCheck Detection Rules Catalog (`docs/detection-rules.md`)

Every signal in TrustCheck is deterministic, pure, and unit-tested. Below is the complete specification of all rules across `url_rules.py`, `text_rules.py`, and `upi_rules.py`, including weights and false-positive safeguards.

---

## 1. URL & Domain Rules (`trustcheck/url_rules.py`)

Official domains for major Indian institutions (`sbi.co.in`, `onlinesbi.sbi`, `hdfcbank.com`, `icicibank.com`, `axisbank.com`, `paytm.com`, `phonepe.com`, `jio.com`, `airtel.in`, `irctc.co.in`, `indiapost.gov.in`, `incometax.gov.in`, `uidai.gov.in`, `epfindia.gov.in`, `parivahan.gov.in`, `bescom.karnataka.gov.in`, `amazon.in`, `flipkart.com`, etc.) are whitelisted upfront to guarantee zero false positives on legitimate links.

| Rule ID | Category | Weight | Trigger Condition | Rationale |
| :--- | :--- | :--- | :--- | :--- |
| `url_apk_download` | `url` | `65` | URL path ends with `.apk` | Banking, KYC, and electricity scams in India frequently distribute sideloaded Android trojans (`SBI_KYC.apk`) via SMS/WhatsApp to intercept OTPs. |
| `url_brand_impersonation` | `url` | `60` | Unofficial domain contains an Indian brand keyword, spoofs `gov.in`, or has Levenshtein edit distance `<= 2` (after homoglyph normalization `0→o`, `1→i`, `rn→m`) | Catches both compound phishing domains (`yonosbi-kyc.top`, `indiapost-gov.org`) and typosquats (`hdfcbankk.com`, `ic1cibank.com`). |
| `url_ip_host` | `url` | `50` | Hostname is a raw IPv4 address (`http://103.45.67.89/...`) | Legitimate Indian banks, utilities, and couriers never serve customer portals over raw IP addresses. |
| `url_punycode` | `url` | `50` | Hostname contains `xn--` IDN Punycode prefix | Used in homograph attacks to visually spoof ASCII bank domains using lookalike Unicode scripts. |
| `url_phishing_pattern` | `url` | `38` | Host or path contains `-kyc`, `kyc-`, `-verify`, `-update`, `-unblock`, `-pan`, `-reward`, `-refund`, `-claim` | Phishing kits routinely hyphenate action lures into disposable domain names. |
| `url_excess_subdomains` | `url` | `32` | Domain has `>= 3` subdomain levels before the registrable domain | Attackers prepend `onlinesbi.com.login.verify.` to push the actual registrable domain off mobile address bars. |
| `url_risky_tld` | `url` | `30` | Top-level domain is in `.xyz`, `.top`, `.click`, `.buzz`, `.loan`, `.work`, `.vip`, `.icu`, `.tk`, `.ml`, `.cf`, `.ga`, `.gq`, `.online`, `.site`, `.live`, `.shop`, `.rest`, `.sbs`, `.cfd`, `.ink` | Cheap bulk-registered TLDs disproportionately used in Indian SMS blasting campaigns. |
| `url_shortener` | `url` | `28` | Domain is a link shortener (`bit.ly`, `tinyurl.com`, `rb.gy`, `cutt.ly`, `shorturl.at`, `t.co`, `is.gd`, `tiny.cc`) | Obscures the true destination host until clicked. Alone it scores `< 30` (Safe), but combined with urgency or KYC lures it escalates risk. |

---

## 2. Text & Social Engineering Rules (`trustcheck/text_rules.py`)

All text rules evaluate English, Hindi (Devanagari), and Hinglish (Romanized Hindi) patterns.

### False-Positive Safeguard: Defensive OTP Warning Check
Legitimate bank OTP messages contain words like `"OTP"`, `"valid for 10 mins"`, and `"SBI Debit Card"`. `has_defensive_otp_warning()` detects phrases such as `"Do NOT share this OTP"`, `"Never share your OTP/PIN"`, or `"यह ओटीपी किसी के साथ साझा न करें"` and suppresses credential-solicitation flags so genuine transactional OTPs score `0` (`safe`).

| Rule ID | Category | Weight | Trigger Condition | Rationale |
| :--- | :--- | :--- | :--- | :--- |
| `text_remote_access` | `text` | `68` | Mentions `AnyDesk`, `TeamViewer`, `QuickSupport`, `RustDesk`, `AirDroid`, `एनीडेस्क`, or `screen share app` | Scammers pose as bank/refund support and ask victims to install remote desktop tools to watch OTPs and drain accounts. |
| `text_digital_arrest` | `text` | `68` | Mentions `digital arrest`, `डिजिटल अरेस्ट`, `giraftari warrant`, or CBI/ED/NCB/Supreme Court video-call interrogation & money-laundering warrants | High-severity extortion scam coercing victims onto Skype/WhatsApp video calls under fake "house arrest". |
| `text_otp_pin_request` | `text` | `58` | Actively asks user to share, send, reply with, or tell their `OTP`, `CVV`, `ATM PIN`, or `MPIN` (`ओटीपी शेयर करें`, `otp batao`) | Legitimate institutions never ask a customer to read back or forward an OTP or CVV. |
| `text_electricity_disconnect` | `text` | `52` | Threatens tonight's electricity disconnection (`electricity power will be disconnected`, `बिजली कनेक्शन काट दिया जाएगा`, `bijli kat jayegi`) | Classic Indian utility scam forcing panic calls to a scammer's personal mobile number. |
| `text_parcel_customs` | `text` | `52` | Claims a courier/FedEx/India Post parcel was seized by customs or contains illegal items (`पार्सल कस्टम्स द्वारा जब्त`) | Used as the opening hook for customs clearance extortion or digital-arrest escalations. |
| `text_job_task_fee` | `text` | `48` | Promises high daily WFH pay (`Earn ₹3,000–₹8,000 per day`), YouTube like/subscribe tasks, Telegram prepaid tasks, or upfront registration fees (`घर बैठे कमाएं`, `रजिस्ट्रेशन फीस`) | Task scams lure victims with small initial payouts before demanding escalating "prepaid task" deposits. |
| `text_lottery_prize` | `text` | `45` | Claims lottery win, KBC lucky draw, or expiring bank reward points (`लॉटरी जीती`, `रिवॉर्ड पॉइंट्स समाप्त`) | Lures victims into phishing forms or advance-fee payments to claim non-existent prizes. |
| `text_kyc_pan_aadhaar` | `text` | `38` | Claims KYC, PAN, or Aadhaar is expired/suspended and demands immediate update (`केवाईसी अपडेट`, `पैन कार्ड बंद`) | Primary pretext used in Indian banking smishing. |
| `text_account_blocked` | `text` | `38` | Threatens that bank account, YONO, or netbanking has been blocked/frozen (`खाता ब्लॉक`, `account band ho jayega`) | Induces panic so victims click lookalike verification links without inspecting the domain. |
| `text_urgency_threat` | `text` | `22` | Artificial countdowns (`immediately`, `within 24 hours`, `tonight at 9:30 PM`, `turant`, `तुरंत`, `अंतिम चेतावनी`) | Social engineering amplifier designed to bypass critical thinking. |

---

## 3. UPI & VPA Rules (`trustcheck/upi_rules.py`)

| Rule ID | Category | Weight | Trigger Condition | Rationale |
| :--- | :--- | :--- | :--- | :--- |
| `upi_pin_to_receive` | `upi` | `72` | Instructs user to enter their UPI PIN to *receive* money, refund, or cashback (`enter UPI PIN to receive`, `पैसे प्राप्त करने के लिए यूपीआई पिन दर्ज करें`, `paisa paane ke liye pin daalein`) | Fundamental UPI invariant: **A UPI PIN is never required to receive money.** Any request asking for a PIN to receive funds is 100% fraudulent. |
| `upi_collect_trick` | `upi` | `62` | Instructs user to approve a collect request or click `"Pay"` to receive a refund/payout | Exploits confusion between incoming credit notifications and outgoing UPI collect requests. |
| `upi_suspicious_vpa` | `upi` | `46` | VPA username contains official-sounding keywords (`refund`, `kyc`, `verify`, `helpline`, `support`, `sbi`, `hdfc`, `rbi`, `pmcare`, `uppcl`, `bescom`) on consumer handles (`@ybl`, `@okaxis`, etc.) | Scammers create personal UPI aliases like `refund.sbi@ybl` or `kyc.verify@okaxis` to make collect requests appear official. |
