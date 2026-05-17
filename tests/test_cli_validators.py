"""Unit tests for CLI argument validators."""

import os
import tempfile

import click
import pytest

from pyqualify.cli.validators import validate_html_filename, validate_path, validate_url


class TestValidateUrl:
    """Tests for validate_url."""

    def test_valid_http_url(self):
        assert validate_url("http://example.com") == "http://example.com"

    def test_valid_https_url(self):
        assert validate_url("https://example.com") == "https://example.com"

    def test_valid_url_with_path(self):
        url = "https://example.com/path/to/page"
        assert validate_url(url) == url

    def test_valid_url_with_port(self):
        url = "http://localhost:8080"
        assert validate_url(url) == url

    def test_valid_url_with_query(self):
        url = "https://example.com/search?q=test"
        assert validate_url(url) == url

    def test_invalid_scheme_ftp(self):
        with pytest.raises(click.BadParameter, match="must use http or https"):
            validate_url("ftp://example.com")

    def test_no_scheme(self):
        with pytest.raises(click.BadParameter, match="must use http or https"):
            validate_url("example.com")

    def test_empty_string(self):
        with pytest.raises(click.BadParameter, match="must use http or https"):
            validate_url("")

    def test_missing_hostname(self):
        with pytest.raises(click.BadParameter, match="must include a valid hostname"):
            validate_url("http://")

    def test_scheme_only(self):
        with pytest.raises(click.BadParameter, match="must include a valid hostname"):
            validate_url("https://")


class TestValidatePath:
    """Tests for validate_path."""

    def test_existing_file(self):
        fd, path = tempfile.mkstemp()
        os.close(fd)
        try:
            assert validate_path(path) == path
        finally:
            os.unlink(path)

    def test_existing_directory(self):
        with tempfile.TemporaryDirectory() as d:
            assert validate_path(d) == d

    def test_nonexistent_path(self):
        with pytest.raises(click.BadParameter, match="does not exist"):
            validate_path("/nonexistent/path/that/does/not/exist")

    def test_empty_path(self):
        with pytest.raises(click.BadParameter, match="does not exist"):
            validate_path("")


class TestValidateHtmlFilename:
    """Tests for validate_html_filename."""

    def test_valid_simple_filename(self):
        assert validate_html_filename("report.html") == "report.html"

    def test_valid_filename_with_dashes(self):
        assert validate_html_filename("my-report-2024.html") == "my-report-2024.html"

    def test_valid_filename_with_underscores(self):
        assert validate_html_filename("analysis_output.html") == "analysis_output.html"

    def test_valid_single_char(self):
        assert validate_html_filename("a") == "a"

    def test_valid_255_chars(self):
        filename = "a" * 255
        assert validate_html_filename(filename) == filename

    def test_empty_filename(self):
        with pytest.raises(click.BadParameter, match="must not be empty"):
            validate_html_filename("")

    def test_too_long_filename(self):
        with pytest.raises(click.BadParameter, match="at most 255 characters"):
            validate_html_filename("a" * 256)

    def test_invalid_char_less_than(self):
        with pytest.raises(click.BadParameter, match="invalid character"):
            validate_html_filename("report<1>.html")

    def test_invalid_char_greater_than(self):
        with pytest.raises(click.BadParameter, match="invalid character"):
            validate_html_filename("report>1.html")

    def test_invalid_char_colon(self):
        with pytest.raises(click.BadParameter, match="invalid character"):
            validate_html_filename("report:1.html")

    def test_invalid_char_pipe(self):
        with pytest.raises(click.BadParameter, match="invalid character"):
            validate_html_filename("report|1.html")

    def test_invalid_char_question_mark(self):
        with pytest.raises(click.BadParameter, match="invalid character"):
            validate_html_filename("report?.html")

    def test_invalid_char_asterisk(self):
        with pytest.raises(click.BadParameter, match="invalid character"):
            validate_html_filename("report*.html")

    def test_invalid_char_null_byte(self):
        with pytest.raises(click.BadParameter, match="invalid character"):
            validate_html_filename("report\x00.html")

    def test_invalid_char_control_character(self):
        with pytest.raises(click.BadParameter, match="invalid character"):
            validate_html_filename("report\x01.html")

    def test_invalid_char_double_quote(self):
        with pytest.raises(click.BadParameter, match="invalid character"):
            validate_html_filename('report"name.html')

    def test_invalid_char_backslash(self):
        with pytest.raises(click.BadParameter, match="invalid character"):
            validate_html_filename("report\\name.html")

    def test_invalid_char_forward_slash(self):
        with pytest.raises(click.BadParameter, match="invalid character"):
            validate_html_filename("report/name.html")

