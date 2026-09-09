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
    readme = (ROOT / "README.md").read_text()
    for command in ("info", "set-pin", "change-pin", "reset"):
        assert f"hirsch-securefido {command}" in readme
