"""
Encoding-safety tests.

A legacy Windows console (cp1252) or a redirected ASCII stream cannot encode
'✓'. Printing it raises UnicodeEncodeError, which on the set-pin and
change-pin paths would crash AFTER the token had already been modified: the
PIN really changed, but the operator sees a traceback instead of confirmation
and cannot tell whether it worked.

These tests pin the ASCII fallback in place.
"""

from __future__ import annotations

import io
import subprocess
import sys

import pytest

from hirsch_securefido import cli


class AsciiStream(io.TextIOBase):
    """Stand-in for a cp1252/ASCII console."""

    encoding = "cp1252"

    def isatty(self):
        return False


def test_detects_an_ascii_only_stream():
    assert cli._supports_unicode(AsciiStream()) is False


def test_detects_a_utf8_stream():
    stream = AsciiStream()
    stream.encoding = "utf-8"
    assert cli._supports_unicode(stream) is True


def test_unknown_encoding_falls_back_safely():
    stream = AsciiStream()
    stream.encoding = "not-a-real-codec"
    assert cli._supports_unicode(stream) is False


def test_missing_encoding_attribute_is_handled():
    class NoEncoding(io.TextIOBase):
        encoding = None

    assert cli._supports_unicode(NoEncoding()) is False


@pytest.mark.parametrize(
    "glyph",
    [cli.GLYPH_OK, cli.GLYPH_FAIL, cli.GLYPH_WARN, cli.GLYPH_BULLET, cli.GLYPH_ARROW],
)
def test_active_glyphs_encode_in_the_current_console(glyph):
    """Whatever glyph set is active must be printable right now."""
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    glyph.encode(encoding)


def test_ascii_fallbacks_are_pure_ascii():
    """When Unicode is unavailable the replacements must be 7-bit clean."""
    for fallback in ("+", "x", "!", "*", "->"):
        fallback.encode("ascii")


def test_glyphs_are_selected_not_hardcoded():
    """
    The module must choose glyphs via UNICODE_OK rather than embedding the
    Unicode characters unconditionally. Reimporting under a forced ASCII
    stdout must yield printable ASCII.
    """
    import importlib

    real_stdout = sys.stdout
    try:
        sys.stdout = AsciiStream()
        reloaded = importlib.reload(cli)
        assert reloaded.UNICODE_OK is False
        for glyph in (
            reloaded.GLYPH_OK,
            reloaded.GLYPH_FAIL,
            reloaded.GLYPH_WARN,
            reloaded.GLYPH_BULLET,
            reloaded.GLYPH_ARROW,
        ):
            # Must be encodable by a cp1252 console; this is the exact
            # operation that raised UnicodeEncodeError before the fix.
            glyph.encode("cp1252")
    finally:
        sys.stdout = real_stdout
        importlib.reload(cli)


# ---------------------------------------------------------------------------
# END-TO-END under a real cp1252 console
# ---------------------------------------------------------------------------
def _run_under_cp1252(args):
    import os

    env = dict(os.environ, PYTHONIOENCODING="cp1252")
    return subprocess.run(
        [sys.executable, "-m", "hirsch_securefido", *args],
        capture_output=True, text=True, env=env, timeout=60, input="",
    )


def test_help_survives_a_cp1252_console():
    proc = _run_under_cp1252(["--help"])
    assert proc.returncode == 0
    assert "UnicodeEncodeError" not in proc.stderr


def test_error_path_survives_a_cp1252_console():
    """
    The no-device error prints the failure glyph. On cp1252 this used to
    raise UnicodeEncodeError instead of the intended message.
    """
    proc = _run_under_cp1252(["info"])
    assert "UnicodeEncodeError" not in proc.stderr, proc.stderr
    assert proc.returncode == 2
    assert "No Hirsch FIDO2 token found" in proc.stderr


def test_list_path_survives_a_cp1252_console():
    proc = _run_under_cp1252(["list"])
    assert "UnicodeEncodeError" not in proc.stderr, proc.stderr
    assert proc.returncode == 2
