"""
Packaging invariants.

These guard the things that silently break a release: a version that drifts
between pyproject and the package, a missing console-script entry point, or
credential-management code leaking back into this device-config-only build.
"""

from __future__ import annotations

from pathlib import Path

import tomllib

import hirsch_securefido

ROOT = Path(__file__).resolve().parent.parent


def _pyproject() -> dict:
    with open(ROOT / "pyproject.toml", "rb") as fh:
        return tomllib.load(fh)


def test_version_matches_pyproject():
    assert _pyproject()["project"]["version"] == hirsch_securefido.__version__


def test_console_script_entry_point_resolves():
    script = _pyproject()["project"]["scripts"]["hirsch-securefido"]
    assert script == "hirsch_securefido.cli:main"

    module_path, func_name = script.split(":")
    import importlib

    module = importlib.import_module(module_path)
    assert callable(getattr(module, func_name))


def test_requires_python_supports_310():
    assert _pyproject()["project"]["requires-python"] == ">=3.10"


def test_fido2_is_the_only_hard_dependency():
    """pyscard must stay optional so Homebrew needs no PCSC toolchain."""
    deps = _pyproject()["project"]["dependencies"]
    assert len(deps) == 1
    assert deps[0].startswith("fido2")
    extras = _pyproject()["project"]["optional-dependencies"]
    assert any(d.startswith("pyscard") for d in extras["pcsc"])


def test_public_api_is_the_four_config_operations():
    for name in ("get_device_info", "set_pin", "change_pin", "factory_reset"):
        assert hasattr(hirsch_securefido, name)


def test_formula_declares_matching_version():
    formula = (ROOT / "Formula" / "hirsch-securefido.rb").read_text()
    assert hirsch_securefido.__version__ in formula
    assert 'include Language::Python::Virtualenv' in formula


def test_readme_documents_every_command():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for command in ("info", "set-pin", "change-pin", "reset"):
        assert f"hirsch-securefido {command}" in readme


def test_readme_states_provenance_honestly():
    """
    Only `info` is a port of the Windows app's device-details view; set-pin,
    change-pin, and reset did not exist there and were written new. The README
    must not claim otherwise.
    """
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "ported from the Windows app" in readme
    assert "new" in readme

    original = ROOT / "hirsch_securefido_cred_manager.py"
    if original.exists():
        source = original.read_text(encoding="utf-8")
        # Guard the claim itself: if the original never called these, the
        # docs must keep describing them as new work.
        assert "set_pin" not in source
        assert "change_pin" not in source
        assert "ctap2.reset" not in source


def test_sdist_excludes_scratch_diagnostics():
    """
    scripts/_*.py are throwaway diagnostics. The hatch sdist config must drop
    them, or a stray debug script ships to PyPI.
    """
    with open(ROOT / "pyproject.toml", "rb") as fh:
        config = tomllib.load(fh)
    exclude = config["tool"]["hatch"]["build"]["targets"]["sdist"]["exclude"]
    assert "scripts/_*.py" in exclude


def test_referenced_scripts_exist():
    """
    Docs and the formula name helper scripts by path. A renamed or deleted
    script leaves instructions that fail when an operator follows them.
    """
    import re

    referenced: set[str] = set()
    for name in ("README.md", "PUBLISHING.md", "HOMEBREW.md"):
        path = ROOT / name
        if path.exists():
            referenced |= set(
                re.findall(r"scripts/[\w.-]+\.(?:sh|py)", path.read_text(encoding="utf-8"))
            )

    formula = (ROOT / "Formula" / "hirsch-securefido.rb").read_text(encoding="utf-8")
    referenced |= set(re.findall(r"scripts/[\w.-]+\.(?:sh|py)", formula))

    missing = [rel for rel in referenced if not (ROOT / rel).exists()]
    assert not missing, f"referenced but missing: {missing}"


def test_homebrew_guide_documents_the_release_order():
    """
    Homebrew builds from the PyPI sdist, so publishing to PyPI must come
    first. A guide that omits this leads to an unresolvable sha256.
    """
    guide = (ROOT / "HOMEBREW.md").read_text(encoding="utf-8")
    assert "brew tap hirschsecure/tap" in guide
    assert "brew install --build-from-source" in guide
    assert "brew audit" in guide
    # The ordering constraint and the formula-vs-cask decision.
    lowered = guide.lower()
    assert "publish to pypi" in lowered
    assert "cask" in lowered
