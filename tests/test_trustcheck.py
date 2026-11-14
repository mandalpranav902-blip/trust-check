"""Comprehensive test suite for TrustCheck (32 test cases covering scams and safe messages).

Compatible with both `pytest` and `python3 -m unittest`.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from api.index import _validate_and_analyze
from trustcheck import (
    analyze_message,
    enrich_with_gemini,
    evaluate_deterministic,
    evaluate_text,
    evaluate_upi,
    evaluate_urls,
    extract_all,
    extract_amounts,
    extract_phone_numbers,
    extract_upi_ids,
    extract_urls,
)


# ---------------------------------------------------------------------------
# 1. Entity Extraction Tests
# ---------------------------------------------------------------------------
def test_01_extract_explicit_and_bare_urls() -> None:
    text = "Dear customer, update PAN at https://sbi-kyc-online.xyz/login or visit bit.ly/3kYcNow immediately."
    urls = extract_urls(text)
    assert "https://sbi-kyc-online.xyz/login" in urls
    assert "bit.ly/3kYcNow" in urls


def test_02_extract_upi_ids_ignores_emails() -> None:
    text = "Send refund request to refund.sbi@ybl or merchant99@okaxis. For email write to support@gmail.com."
    upis = extract_upi_ids(text)
    assert "refund.sbi@ybl" in upis
    assert "merchant99@okaxis" in upis
    assert "support@gmail.com" not in upis


def test_03_extract_indian_phone_numbers_and_amounts() -> None:
    text = "Call electricity officer at +91 9876543210 or 87654-32109 to pay pending bill of ₹4,500 or Rs. 1,200."
    phones = extract_phone_numbers(text)
    amounts = extract_amounts(text)
    assert len(phones) == 2
    assert "₹4,500" in amounts
    assert "Rs. 1,200" in amounts


# ---------------------------------------------------------------------------
# 2. URL Rules Tests (Brand Impersonation, Lookalikes, Shorteners, Risky TLDs)
# ---------------------------------------------------------------------------
def test_04_url_sbi_brand_impersonation_and_risky_tld() -> None:
    flags = evaluate_urls(["https://sbi-kyc-update.xyz/verify"])
    ids = {f.id for f in flags}
    assert "url_brand_impersonation" in ids
    assert "url_risky_tld" in ids
    assert "url_phishing_pattern" in ids


def test_05_url_levenshtein_typosquatting_hdfc_and_icici() -> None:
    flags_hdfc = evaluate_urls(["https://hdfcbankk.com/netbanking"])
    flags_icici = evaluate_urls(["https://ic1cibank.com/login"])
    assert any(f.id == "url_brand_impersonation" for f in flags_hdfc)
    assert any(f.id == "url_brand_impersonation" for f in flags_icici)


def test_06_url_ip_host_and_apk_malware_link() -> None:
    flags = evaluate_urls(["http://103.45.67.89/SBI_Quick_KYC.apk"])
    ids = {f.id for f in flags}
    assert "url_ip_host" in ids
    assert "url_apk_download" in ids


def test_07_url_punycode_and_excess_subdomains() -> None:
    flags = evaluate_urls(["https://xn--onlinesbi-99a.com", "https://login.secure.verify.portal.example.org"])
    ids = {f.id for f in flags}
    assert "url_punycode" in ids
    assert "url_excess_subdomains" in ids


def test_08_url_shortener_detection() -> None:
    flags = evaluate_urls(["https://rb.gy/xyz123"])
    assert any(f.id == "url_shortener" for f in flags)


# ---------------------------------------------------------------------------
# 3. Real-Looking Indian Scam Samples (English, Hindi Devanagari, Hinglish)
# ---------------------------------------------------------------------------
def test_09_scam_sbi_kyc_pan_blocked_sms() -> None:
    msg = (
        "Dear Customer, Your SBI YONO account has been blocked today because your PAN card is expired. "
        "Update your KYC immediately at https://yonosbi-kyc-verify.top/login within 24 hours."
    )
    res = evaluate_deterministic(msg)
    assert res.verdict == "scam"
    assert res.score >= 65
    assert any(f.id == "url_brand_impersonation" for f in res.flags)
    assert any(f.id == "text_kyc_pan_aadhaar" for f in res.flags)


def test_10_scam_electricity_disconnection_tonight() -> None:
    msg = (
        "Dear consumer, your Electricity power will be disconnected tonight at 9:30 PM from BESCOM office "
        "because your previous month bill was not updated. Immediately contact electricity officer 9812345678."
    )
    res = evaluate_deterministic(msg)
    assert res.verdict == "scam"
    assert res.score >= 65
    assert "Electricity" in res.scam_type


def test_11_scam_upi_enter_pin_to_receive_money() -> None:
    msg = (
        "Cashback Alert: Rs. 2,500 credited from PM Relief Desk via refund.sbi@ybl. "
        "Click Pay on the collect request and enter your 4-digit UPI PIN to receive money in your bank account."
    )
    res = evaluate_deterministic(msg)
    assert res.verdict == "scam"
    assert res.score >= 75
    flag_ids = {f.id for f in res.flags}
    assert "upi_pin_to_receive" in flag_ids
    assert "upi_suspicious_vpa" in flag_ids


def test_12_scam_fake_job_youtube_telegram_prepaid_task() -> None:
    msg = (
        "Part-time WFH job! Earn ₹3,000 to ₹8,000 per day simply by liking YouTube videos. "
        "Complete VIP Telegram prepaid task and pay a refundable registration fee of Rs 1,000 to claim payout."
    )
    res = evaluate_deterministic(msg)
    assert res.verdict == "scam"
    assert res.score >= 65
    assert any(f.id == "text_job_task_fee" for f in res.flags)


def test_13_scam_fedex_parcel_customs_seizure() -> None:
    msg = (
        "URGENT: Your FedEx parcel has been seized by customs in Mumbai after illegal items and fake passports "
        "were found inside your parcel. Pay customs clearance fee immediately or face arrest."
    )
    res = evaluate_deterministic(msg)
    assert res.verdict == "scam"
    assert res.score >= 65
    assert any(f.id == "text_parcel_customs" for f in res.flags)


def test_14_scam_digital_arrest_cbi_warrant() -> None:
    msg = (
        "NOTICE: Non-bailable warrant issued against your Aadhaar by CBI and Enforcement Directorate in a "
        "money laundering case. You are placed under Digital Arrest on Skype video call. Do not disconnect."
    )
    res = evaluate_deterministic(msg)
    assert res.verdict == "scam"
    assert res.score >= 65
    assert any(f.id == "text_digital_arrest" for f in res.flags)


def test_15_scam_remote_access_anydesk_support() -> None:
    msg = (
        "Dear customer, to unblock your HDFC debit card and process your refund of Rs 4,899, "
        "please download AnyDesk remote support app from Play Store and share the 9-digit code."
    )
    res = evaluate_deterministic(msg)
    assert res.verdict == "scam"
    assert res.score >= 65
    assert any(f.id == "text_remote_access" for f in res.flags)


def test_16_scam_hindi_devanagari_kyc_and_electricity() -> None:
    msg = (
        "प्रिय ग्राहक, आपका एसबीआई खाता ब्लॉक हो गया है क्योंकि केवाईसी अपडेट नहीं है। "
        "आज रात बिजली कनेक्शन काट दिया जाएगा। तुरंत https://sbi-update.xyz पर पैन कार्ड अपडेट करें।"
    )
    res = evaluate_deterministic(msg)
    assert res.verdict == "scam"
    assert res.score >= 65
    flag_ids = {f.id for f in res.flags}
    assert "text_account_blocked" in flag_ids or "text_kyc_pan_aadhaar" in flag_ids


def test_17_scam_hindi_devanagari_upi_pin_and_digital_arrest() -> None:
    msg = (
        "आपके खिलाफ सीबीआई अधिकारी द्वारा डिजिटल अरेस्ट और गिरफ्तारी वारंट जारी किया गया है। "
        "रिफंड पैसे प्राप्त करने के लिए अपना यूपीआई पिन दर्ज करें।"
    )
    res = evaluate_deterministic(msg)
    assert res.verdict == "scam"
    assert res.score >= 70
    flag_ids = {f.id for f in res.flags}
    assert "text_digital_arrest" in flag_ids
    assert "upi_pin_to_receive" in flag_ids


def test_18_scam_hinglish_electricity_and_upi_pin() -> None:
    msg = (
        "Aapka bijli bill update nahi hua hai, aaj raat bijli kat jayegi. "
        "Turant Rs 500 cashback paane ke liye apna UPI PIN daalein refund.uppcl@okaxis par."
    )
    res = evaluate_deterministic(msg)
    assert res.verdict == "scam"
    assert res.score >= 65
    flag_ids = {f.id for f in res.flags}
    assert "text_electricity_disconnect" in flag_ids
    assert "upi_pin_to_receive" in flag_ids


def test_19_scam_lottery_kbc_and_expiring_reward_points() -> None:
    msg = (
        "Congratulations! You have won KBC lucky draw prize of ₹25,00,000 and your HDFC reward points "
        "worth Rs 6,450 are expiring today. Redeem your reward points now at https://hdfc-reward-claim.buzz"
    )
    res = evaluate_deterministic(msg)
    assert res.verdict == "scam"
    assert res.score >= 65
    assert any(f.id == "text_lottery_prize" for f in res.flags)


def test_20_scam_otp_harvesting_request() -> None:
    msg = (
        "Hello sir, I accidentally sent my OTP to your number. Please share the 6-digit OTP immediately "
        "and provide CVV so our executive can cancel the charge."
    )
    res = evaluate_deterministic(msg)
    assert res.verdict == "scam"
    assert res.score >= 65
    assert any(f.id == "text_otp_pin_request" for f in res.flags)


# ---------------------------------------------------------------------------
# 4. Suspicious (Medium Risk, 30-64) Calibration Tests
# ---------------------------------------------------------------------------
def test_21_suspicious_single_shortener_with_urgency() -> None:
    msg = "Please review your pending document immediately before 5 PM today at https://bit.ly/3docCheck"
    res = evaluate_deterministic(msg)
    assert res.verdict == "suspicious"
    assert 30 <= res.score < 65


def test_22_suspicious_vpa_without_pin_coercion() -> None:
    msg = "Please verify your merchant details with support.paytm@ybl for ticket #4021."
    res = evaluate_deterministic(msg)
    assert res.verdict == "suspicious"
    assert 30 <= res.score < 65


# ---------------------------------------------------------------------------
# 5. Legitimate / Safe Messages (Low False-Positive Verification)
# ---------------------------------------------------------------------------
def test_23_safe_legitimate_bank_otp_sms() -> None:
    msg = (
        "482910 is your OTP for transaction of INR 1,450.00 at Amazon on your SBI Debit Card ending 4012. "
        "Valid for 10 mins. Do NOT share this OTP with anyone. Bank never asks for OTP/PIN."
    )
    res = evaluate_deterministic(msg)
    assert res.verdict == "safe"
    assert res.score < 30
    assert len(res.flags) == 0


def test_24_safe_legitimate_india_post_and_amazon_delivery() -> None:
    msg = (
        "Your India Post Speed Post article EE491029312IN has been dispatched. "
        "Track your shipment at https://www.indiapost.gov.in or https://www.amazon.in/orders"
    )
    res = evaluate_deterministic(msg)
    assert res.verdict == "safe"
    assert res.score == 0


def test_25_safe_legitimate_hdfc_and_sbi_official_urls() -> None:
    msg = (
        "Log in to official portals at https://www.hdfcbank.com and https://onlinesbi.sbi "
        "to view your monthly e-statement."
    )
    res = evaluate_deterministic(msg)
    assert res.verdict == "safe"
    assert res.score == 0


def test_26_safe_normal_friend_upi_conversation() -> None:
    msg = "Hey Rohan, I sent ₹450 for dinner on rahul.sharma@okicici. Let me know once you get it!"
    res = evaluate_deterministic(msg)
    assert res.verdict == "safe"
    assert res.score == 0


def test_27_safe_hindi_defensive_otp_message() -> None:
    msg = (
        "आपके खाते से ₹500 के लेनदेन के लिए ओटीपी 839201 है। "
        "यह ओटीपी किसी के साथ साझा न करें। बैंक कभी ओटीपी नहीं मांगता।"
    )
    res = evaluate_deterministic(msg)
    assert res.verdict == "safe"
    assert res.score == 0


def test_28_safe_irctc_ticket_confirmation() -> None:
    msg = (
        "PNR 2419084122: Train 12952 NDLS MMCT Rajdhani confirmed, Coach B4 Berth 22. "
        "Check status on https://www.irctc.co.in."
    )
    res = evaluate_deterministic(msg)
    assert res.verdict == "safe"
    assert res.score == 0


# ---------------------------------------------------------------------------
# 6. Gemini Fallback & Invariant Tests
# ---------------------------------------------------------------------------
def test_29_gemini_missing_key_falls_back_cleanly() -> None:
    det = evaluate_deterministic(
        "Enter your UPI PIN to receive Rs 5,000 refund from refund.sbi@ybl immediately."
    )
    enriched = enrich_with_gemini("test input", det, api_key="")
    assert enriched.ai_used is False
    assert enriched.verdict == det.verdict
    assert enriched.score == det.score
    assert len(enriched.explanation) > 20


def test_30_gemini_never_alters_verdict_or_score() -> None:
    det = evaluate_deterministic(
        "Your electricity power will be disconnected tonight. Call 9876543210 immediately."
    )
    with patch(
        "trustcheck.gemini._call_via_rest",
        return_value=("Electricity Disconnection Fraud", "Custom AI explanation citing the evidence."),
    ):
        with patch("trustcheck.gemini._call_via_google_genai_sdk", side_effect=ImportError):
            enriched = enrich_with_gemini("raw", det, api_key="fake-test-key")
            assert enriched.ai_used is True
            assert enriched.verdict == det.verdict
            assert enriched.score == det.score
            assert enriched.scam_type == "Electricity Disconnection Fraud"
            assert enriched.explanation == "Custom AI explanation citing the evidence."


# ---------------------------------------------------------------------------
# 7. API Validation & Contract Tests
# ---------------------------------------------------------------------------
def test_31_api_rejects_empty_and_oversized_inputs() -> None:
    status_empty, _ = _validate_and_analyze({"input": "   "})
    status_long, _ = _validate_and_analyze({"input": "a" * 2001})
    status_bad_type, _ = _validate_and_analyze({"input": 12345})
    assert status_empty == 422
    assert status_long == 422
    assert status_bad_type == 422


def test_32_api_returns_complete_schema_for_valid_input() -> None:
    with patch("trustcheck.gemini._is_valid_api_key", return_value=False):
        status, body = _validate_and_analyze(
            {
                "input": "Dear customer, your SBI account is blocked. Update PAN at https://sbi-kyc.xyz now."
            }
        )
    assert status == 200
    assert body["verdict"] == "scam"
    assert 65 <= body["score"] <= 100
    assert isinstance(body["scam_type"], str)
    assert isinstance(body["flags"], list) and len(body["flags"]) >= 2
    assert isinstance(body["explanation"], str) and len(body["explanation"]) > 10
    assert isinstance(body["actions"], list) and len(body["actions"]) >= 1
    assert body["ai_used"] is False


class TrustCheckUnitTestSuite(unittest.TestCase):
    """Unittest runner wrapper so `python3 -m unittest` runs all 32 pytest functions."""

    def test_run_all_cases(self) -> None:
        for name, func in sorted(globals().items()):
            if name.startswith("test_") and callable(func):
                with self.subTest(case=name):
                    func()


if __name__ == "__main__":
    unittest.main()
