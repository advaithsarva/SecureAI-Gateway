"""Phase 13: Unit tests for Phase 6 AI Output Security Filter."""
from app.security.output_filter import OutputSecurityFilter


def test_output_filter_blocks_confidential_canary_leak():
    flt = OutputSecurityFilter()
    raw_output = "Internal leak: CANARY-ACME-2026-SYNTHETIC-9001 disclosed."
    res = flt.inspect_output(raw_output)
    assert res.status == "BLOCKED"
    assert res.blocked is True
    assert "CANARY-ACME-2026-SYNTHETIC-9001" not in res.filtered_response


def test_output_filter_redacts_sensitive_pii_in_response():
    flt = OutputSecurityFilter()
    raw_output = "Please reach out to support.lead@acmelabs.org or call 9876543210."
    res = flt.inspect_output(raw_output)
    assert res.status == "REDACTED"
    assert res.modified is True
    assert res.blocked is False
    assert "[REDACTED_EMAIL]" in res.filtered_response
    assert "[REDACTED_PHONE]" in res.filtered_response


def test_output_filter_passes_safe_response():
    flt = OutputSecurityFilter()
    raw_output = "Binary search trees allow O(log n) lookup on average."
    res = flt.inspect_output(raw_output)
    assert res.status == "PASSED"
    assert res.modified is False
    assert res.blocked is False
    assert res.filtered_response == raw_output
