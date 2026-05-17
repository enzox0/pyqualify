"""Utility functions for PyQualify analysis tool."""

# Maximum evidence length in final output (Requirement 21.4)
EVIDENCE_MAX_LENGTH = 500
TRUNCATION_INDICATOR = "... [truncated]"


def truncate_evidence(evidence: str, max_length: int = EVIDENCE_MAX_LENGTH) -> str:
    """Truncate evidence string to the specified maximum length.

    If the evidence exceeds max_length characters, it is truncated and a
    truncation indicator is appended. The total output (including indicator)
    will not exceed max_length characters.

    If the evidence is within the limit, it is returned unchanged.

    Args:
        evidence: The evidence string to potentially truncate.
        max_length: Maximum allowed length (default 500).

    Returns:
        The original string if within limit, or a truncated version with
        indicator if it exceeds the limit.
    """
    if len(evidence) <= max_length:
        return evidence

    # Reserve space for the truncation indicator
    truncated_length = max_length - len(TRUNCATION_INDICATOR)
    if truncated_length < 0:
        # Edge case: max_length is smaller than the indicator itself
        return evidence[:max_length]

    return evidence[:truncated_length] + TRUNCATION_INDICATOR


def resolve_location(location: str | None, fallback: str = "unknown") -> str:
    """Resolve a location reference, using the most specific known location.

    If the location is None or empty, returns the fallback (most-specific-known
    location). This handles the case where an exact location cannot be determined
    (Requirement 21.2).

    Args:
        location: The location string (URL, file:line, endpoint path).
        fallback: The most specific known location to use if location is unresolved.

    Returns:
        A non-empty location string.
    """
    if location and location.strip():
        return location.strip()
    return fallback
