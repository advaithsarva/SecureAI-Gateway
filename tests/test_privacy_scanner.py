"""Phase 13: Unit tests for Phase 3 Sensitive Data Detection and Redaction."""
from app.security.privacy_scanner import PrivacyScanner


def test_exact_email_and_indian_phone_redaction_example():
    scanner = PrivacyScanner()
    prompt = "My email is example@gmail.com and my phone number is 9876543210."
    res = scanner.scan_and_redact(prompt)
    assert res.detected is True
    assert (
        res.sanitized_text
        == "My email is [REDACTED_EMAIL] and my phone number is [REDACTED_PHONE]."
    )
    assert res.entity_counts.get("EMAIL") == 1
    assert res.entity_counts.get("PHONE") == 1


def test_pan_ip_api_key_and_password_redaction():
    scanner = PrivacyScanner()
    prompt = (
        "Server 192.168.10.25 uses key sk-synth1234567890abcdefghijkl, "
        "PAN ABCDE1234F, and password is MyTempPassword123."
    )
    res = scanner.scan_and_redact(prompt)
    assert res.detected is True
    assert "[REDACTED_IP]" in res.sanitized_text
    assert "[REDACTED_API_KEY]" in res.sanitized_text
    assert "[REDACTED_ID]" in res.sanitized_text
    assert "[REDACTED_PASSWORD]" in res.sanitized_text
    assert "sk-synth1234567890abcdefghijkl" not in res.sanitized_text
    assert "MyTempPassword123" not in res.sanitized_text


def test_configurable_redaction_policy_toggles():
    scanner = PrivacyScanner()
    prompt = "Contact user@example.org from IP 10.0.0.1"
    res = scanner.scan_and_redact(prompt, policy={"redact_emails": True, "redact_ips": False})
    assert "[REDACTED_EMAIL]" in res.sanitized_text
    assert "10.0.0.1" in res.sanitized_text
