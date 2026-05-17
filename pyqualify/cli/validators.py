"""CLI argument validators for PyQualify commands."""

import os
import re
from urllib.parse import urlparse

import click


def validate_url(url: str) -> str:
    """Validate URL format for web and API commands.

    The URL must have an http or https scheme and a non-empty hostname.

    Args:
        url: The URL string to validate.

    Returns:
        The validated URL string.

    Raises:
        click.BadParameter: If the URL is not a valid format.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        raise click.BadParameter(
            f"'{url}' is not a valid URL format."
        )

    if parsed.scheme not in ("http", "https"):
        raise click.BadParameter(
            f"'{url}' must use http or https scheme."
        )

    if not parsed.hostname:
        raise click.BadParameter(
            f"'{url}' must include a valid hostname."
        )

    return url


def validate_path(path: str) -> str:
    """Validate that a file or directory path exists.

    Args:
        path: The file or directory path to validate.

    Returns:
        The validated path string.

    Raises:
        click.BadParameter: If the path does not exist.
    """
    if not os.path.exists(path):
        raise click.BadParameter(
            f"Path '{path}' does not exist."
        )

    return path


# Characters that are invalid in filenames across common operating systems.
# Covers Windows reserved characters and common problematic characters.
_INVALID_FILENAME_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def validate_html_filename(filename: str) -> str:
    """Validate HTML output filename.

    The filename must be between 1 and 255 characters and contain only
    valid filesystem characters.

    Args:
        filename: The HTML output filename to validate.

    Returns:
        The validated filename string.

    Raises:
        click.BadParameter: If the filename is invalid.
    """
    if not filename:
        raise click.BadParameter(
            "HTML output filename must not be empty."
        )

    if len(filename) > 255:
        raise click.BadParameter(
            f"HTML output filename must be at most 255 characters, got {len(filename)}."
        )

    invalid_match = _INVALID_FILENAME_CHARS.search(filename)
    if invalid_match:
        char = invalid_match.group()
        if ord(char) < 32:
            char_repr = f"\\x{ord(char):02x}"
        else:
            char_repr = char
        raise click.BadParameter(
            f"HTML output filename contains invalid character: '{char_repr}'."
        )

    return filename
