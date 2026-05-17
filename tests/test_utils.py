"""Tests for qaai.utils module - evidence truncation and location resolution."""

import pytest

from pyqualify.utils import (
    EVIDENCE_MAX_LENGTH,
    TRUNCATION_INDICATOR,
    resolve_location,
    truncate_evidence,
)


class TestTruncateEvidence:
    """Tests for the truncate_evidence utility function."""

    def test_short_evidence_unchanged(self):
        """Evidence within limit is returned unchanged."""
        evidence = "Short evidence string"
        result = truncate_evidence(evidence)
        assert result == evidence

    def test_exactly_500_chars_unchanged(self):
        """Evidence exactly at the limit is returned unchanged."""
        evidence = "x" * 500
        assert len(evidence) == EVIDENCE_MAX_LENGTH
        result = truncate_evidence(evidence)
        assert result == evidence

    def test_exceeds_500_chars_truncated(self):
        """Evidence exceeding 500 chars is truncated with indicator."""
        evidence = "a" * 600
        result = truncate_evidence(evidence)
        assert len(result) <= EVIDENCE_MAX_LENGTH
        assert result.endswith(TRUNCATION_INDICATOR)

    def test_truncated_output_max_length(self):
        """Truncated output is exactly 500 characters."""
        evidence = "b" * 1000
        result = truncate_evidence(evidence)
        assert len(result) == EVIDENCE_MAX_LENGTH

    def test_501_chars_truncated(self):
        """Evidence at 501 chars (just over limit) is truncated."""
        evidence = "c" * 501
        result = truncate_evidence(evidence)
        assert len(result) <= EVIDENCE_MAX_LENGTH
        assert result.endswith(TRUNCATION_INDICATOR)

    def test_empty_string_unchanged(self):
        """Empty evidence string is returned unchanged."""
        result = truncate_evidence("")
        assert result == ""

    def test_custom_max_length(self):
        """Custom max_length parameter is respected."""
        evidence = "d" * 200
        result = truncate_evidence(evidence, max_length=100)
        assert len(result) <= 100
        assert result.endswith(TRUNCATION_INDICATOR)

    def test_custom_max_length_within_limit(self):
        """Evidence within custom max_length is unchanged."""
        evidence = "e" * 50
        result = truncate_evidence(evidence, max_length=100)
        assert result == evidence

    def test_truncation_preserves_beginning(self):
        """Truncation preserves the beginning of the evidence."""
        evidence = "START" + "x" * 600
        result = truncate_evidence(evidence)
        assert result.startswith("START")

    def test_very_long_evidence(self):
        """Very long evidence (10000 chars) is properly truncated."""
        evidence = "f" * 10000
        result = truncate_evidence(evidence)
        assert len(result) == EVIDENCE_MAX_LENGTH
        assert result.endswith(TRUNCATION_INDICATOR)

    def test_unicode_evidence_truncated(self):
        """Unicode evidence is truncated by character count, not bytes."""
        evidence = "Ã©" * 600
        result = truncate_evidence(evidence)
        assert len(result) <= EVIDENCE_MAX_LENGTH
        assert result.endswith(TRUNCATION_INDICATOR)


class TestResolveLocation:
    """Tests for the resolve_location utility function."""

    def test_valid_url_returned(self):
        """Valid URL location is returned as-is."""
        location = "https://example.com/page"
        result = resolve_location(location)
        assert result == location

    def test_file_with_line_returned(self):
        """File:line location is returned as-is."""
        location = "src/main.py:42"
        result = resolve_location(location)
        assert result == location

    def test_endpoint_path_returned(self):
        """Endpoint path location is returned as-is."""
        location = "/api/v1/users"
        result = resolve_location(location)
        assert result == location

    def test_none_returns_fallback(self):
        """None location returns the fallback."""
        result = resolve_location(None, fallback="/api/v1")
        assert result == "/api/v1"

    def test_empty_string_returns_fallback(self):
        """Empty string location returns the fallback."""
        result = resolve_location("", fallback="https://example.com")
        assert result == "https://example.com"

    def test_whitespace_only_returns_fallback(self):
        """Whitespace-only location returns the fallback."""
        result = resolve_location("   ", fallback="file.py")
        assert result == "file.py"

    def test_default_fallback_is_unknown(self):
        """Default fallback is 'unknown' when not specified."""
        result = resolve_location(None)
        assert result == "unknown"

    def test_location_stripped(self):
        """Location with leading/trailing whitespace is stripped."""
        result = resolve_location("  /api/users  ")
        assert result == "/api/users"

