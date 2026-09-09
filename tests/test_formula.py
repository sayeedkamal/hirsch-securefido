"""
Static validation of the Homebrew formula.

CONSTRAINT: no Ruby interpreter and no macOS host are available in this
environment, so `brew install`, `brew test`, and `brew audit` cannot be run
here, and the formula is never parsed by Ruby. These tests therefore check
the properties that ARE checkable offline: block structure, required Homebrew
fields, version agreement with the package, and that the test block asserts
real behavior. `test_formula_urls_are_reachable` additionally verifies every
download URL over the network when it is available.

The real acceptance path (brew install/test/audit on macOS) is recorded as a
required manual step in PUBLISHING.md.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request
from pathlib import Path

import pytest

import hirsch_securefido

FORMULA_PATH = Path(__file__).resolve().parent.parent / "Formula" / "hirsch-securefido.rb"
FORMULA = FORMULA_PATH.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# STRUCTURE
# ---------------------------------------------------------------------------
def test_class_name_matches_homebrew_convention():
    """Homebrew derives the class name from the file name; a mismatch fails."""
    assert "class HirschSecurefido < Formula" in FORMULA
    assert FORMULA_PATH.name == "hirsch-securefido.rb"


def test_do_end_blocks_are_balanced():
    """A stray do/end is the most common way a formula fails to parse."""
    # Strip comments and heredoc bodies first: prose inside them can contain
    # words that look like block keywords.
    body = re.sub(r"<<~EOS.*?\n\s*EOS", "<<~EOS\nEOS", FORMULA, flags=re.DOTALL)
    body = "\n".join(
        line for line in body.splitlines() if not line.strip().startswith("#")
    )

    # Block openers: a trailing `do`, or `do |args|`, plus class/def and heredocs.
    opens = len(re.findall(r"\bdo\s*(?:\|[^|]*\|)?\s*$", body, re.MULTILINE))
    opens += len(re.findall(r"^\s*(?:class|def)\s", body, re.MULTILINE))
    opens += len(re.findall(r"<<~EOS", body))
    ends = len(re.findall(r"^\s*end\s*$", body, re.MULTILINE))
    ends += len(re.findall(r"^\s*EOS\s*$", body, re.MULTILINE))
    assert opens == ends, f"unbalanced blocks: {opens} open vs {ends} end"


def test_required_fields_present():
    for field in ("desc", "homepage", "url", "sha256", "license"):
        assert re.search(rf"^\s*{field}\s", FORMULA, re.MULTILINE), f"missing {field}"


def test_desc_follows_homebrew_style():
    """`brew audit` rejects a desc that starts with an article or the name."""
    desc = re.search(r'desc\s+"([^"]+)"', FORMULA).group(1)
    assert not desc.lower().startswith(("a ", "an ", "the "))
    assert not desc.lower().startswith("hirsch-securefido")
    assert desc[0].isupper()
    assert not desc.endswith(".")
    assert len(desc) <= 80, f"desc is {len(desc)} chars; audit prefers <= 80"


def test_uses_virtualenv_install():
    assert "include Language::Python::Virtualenv" in FORMULA
    assert "virtualenv_install_with_resources" in FORMULA


def test_declares_python_and_rust_dependencies():
    assert re.search(r'depends_on "python@3\.\d+"', FORMULA)
    # cryptography builds from source under Homebrew and needs Rust.
    assert 'depends_on "rust" => :build' in FORMULA


def test_license_matches_project():
    assert 'license "BSD-3-Clause"' in FORMULA


# ---------------------------------------------------------------------------
# VERSION AGREEMENT
# ---------------------------------------------------------------------------
def test_url_version_matches_package_version():
    version = hirsch_securefido.__version__
    url = re.search(r'^\s*url\s+"([^"]+)"', FORMULA, re.MULTILINE).group(1)
    assert version in url, f"formula url {url} does not reference {version}"


def test_sdist_sha256_is_a_placeholder_or_valid_digest():
    """
    Until the sdist is published the digest is a documented placeholder.
    Once replaced it must be a real 64-char hex digest, never a truncated one.
    """
    sha = re.search(r'^\s*sha256\s+"([^"]+)"', FORMULA, re.MULTILINE).group(1)
    assert sha == "REPLACE_WITH_SDIST_SHA256" or re.fullmatch(r"[0-9a-f]{64}", sha), (
        f"top-level sha256 is neither the placeholder nor a valid digest: {sha}"
    )


# ---------------------------------------------------------------------------
# RESOURCES
# ---------------------------------------------------------------------------
RESOURCES = re.findall(
    r'resource "([^"]+)" do\s*\n\s*url "([^"]+)"\s*\n\s*sha256 "([0-9a-f]{64})"',
    FORMULA,
)


def test_all_python_dependencies_have_resources():
    """
    A virtualenv formula must vendor every transitive dependency. fido2 needs
    cryptography, which needs cffi, which needs pycparser.
    """
    names = {name for name, _, _ in RESOURCES}
    assert {"fido2", "cryptography", "cffi", "pycparser"} <= names


def test_resource_digests_are_full_length():
    for name, _url, sha in RESOURCES:
        assert re.fullmatch(r"[0-9a-f]{64}", sha), f"{name} has a malformed sha256"


def test_no_resource_for_optional_pyscard():
    """pyscard must stay optional so Homebrew needs no PCSC-Lite toolchain."""
    assert "pyscard" not in {name for name, _, _ in RESOURCES}


# ---------------------------------------------------------------------------
# TEST BLOCK
# ---------------------------------------------------------------------------
def test_formula_test_block_asserts_real_behavior():
    block = FORMULA[FORMULA.index("test do"):]
    assert "--version" in block
    # `brew audit` fails a test block that only runs --version.
    for command in ("info", "set-pin", "change-pin", "reset"):
        assert command in block, f"test block does not exercise {command}"
    # Exit code 2 is the no-device contract verified in test_cli.py.
    assert "No Hirsch FIDO2 token found" in block


def test_caveats_do_not_promise_sudo():
    """The macOS port's whole point is that elevation is unnecessary."""
    caveats = re.search(r"def caveats(.*?)\n  end", FORMULA, re.DOTALL).group(1)
    assert "sudo" in caveats.lower()
    assert "No sudo is required" in caveats


# ---------------------------------------------------------------------------
# NETWORK (skipped when offline)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name,url,_sha", RESOURCES)
def test_formula_urls_are_reachable(name, url, _sha):
    """Every vendored resource URL must actually exist on PyPI."""
    request = urllib.request.Request(url, method="HEAD")
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            assert response.status == 200, f"{name}: HTTP {response.status}"
    except urllib.error.URLError as exc:
        pytest.skip(f"network unavailable: {exc}")
