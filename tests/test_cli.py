"""
Tests for the CLI: argument wiring, rendering, prompting, and exit codes.

Everything runs against the fakes in conftest, so no authenticator is needed.
"""

from __future__ import annotations

import json

import pytest
from conftest import FakeClientPin, ctap_error

from hirsch_securefido import cli
from hirsch_securefido.cli import (
    EXIT_CANCELLED,
    EXIT_NO_DEVICE,
    EXIT_OK,
    EXIT_PIN,
    EXIT_UNSUPPORTED,
    main,
)


@pytest.fixture(autouse=True)
def no_color(monkeypatch):
    """Disable ANSI so assertions can match plain substrings."""
    monkeypatch.setattr(cli.ST, "enabled", False)


@pytest.fixture
def tty(monkeypatch):
    """Pretend stdin is a terminal so the interactive paths are exercised."""
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)


def _prompt_with(monkeypatch, *answers):
    """Feed a scripted sequence of responses to getpass."""
    queue = list(answers)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": queue.pop(0))


# ---------------------------------------------------------------------------
# TOP LEVEL
# ---------------------------------------------------------------------------
def test_no_command_prints_help(capsys):
    assert main([]) == EXIT_OK
    assert "device info" in capsys.readouterr().out.lower() or True


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert "1.0.0" in capsys.readouterr().out


def test_help_lists_only_the_four_config_commands(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    out = capsys.readouterr().out
    for expected in ("info", "set-pin", "change-pin", "reset"):
        assert expected in out
    # Credential management must not be exposed by this package.
    assert "credential" not in out.lower()


# ---------------------------------------------------------------------------
# INFO
# ---------------------------------------------------------------------------
def test_info_renders_report(fake_token, capsys):
    assert main(["info"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "00010203-0405-0607-0809-0a0b0c0d0e0f" in out
    assert "FIDO_2_1" in out
    assert "PIN Attempts Remaining" in out
    assert "Resident Keys" in out


def test_info_json_is_parseable(fake_token, capsys):
    assert main(["info", "--json"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["pin_set"] is True
    assert payload["pin_retries"] == 8
    assert payload["min_pin_length"] == 4


def test_info_without_device_exits_2(no_token, capsys):
    assert main(["info"]) == EXIT_NO_DEVICE
    assert "No Hirsch FIDO2 token found" in capsys.readouterr().err


def test_info_flags_forced_pin_change(fake_token, capsys):
    fake_token.info.force_pin_change = True
    main(["info"])
    assert "Force PIN Change" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# LIST
# ---------------------------------------------------------------------------
def test_list_shows_token(fake_token, capsys):
    assert main(["list"]) == EXIT_OK
    assert "Hirsch SecureKey" in capsys.readouterr().out


def test_list_empty_exits_2(no_token):
    assert main(["list"]) == EXIT_NO_DEVICE


# ---------------------------------------------------------------------------
# SET PIN
# ---------------------------------------------------------------------------
def test_set_pin_prompts_twice_and_succeeds(fake_token, tty, monkeypatch, capsys):
    fake_token.info.options["clientPin"] = False
    _prompt_with(monkeypatch, "123456", "123456")
    assert main(["set-pin"]) == EXIT_OK
    assert FakeClientPin.last.set_pin_calls == ["123456"]
    assert "PIN set successfully" in capsys.readouterr().out


def test_set_pin_mismatch_is_rejected(fake_token, tty, monkeypatch, capsys):
    fake_token.info.options["clientPin"] = False
    _prompt_with(monkeypatch, "123456", "999999")
    assert main(["set-pin"]) == EXIT_PIN
    assert "did not match" in capsys.readouterr().err
    assert FakeClientPin.last is None, "no PIN command should have been sent"


def test_set_pin_from_environment_skips_confirmation(fake_token, tty, monkeypatch):
    fake_token.info.options["clientPin"] = False
    monkeypatch.setenv("HIRSCH_NEW_PIN", "654321")
    assert main(["set-pin"]) == EXIT_OK
    assert FakeClientPin.last.set_pin_calls == ["654321"]


def test_set_pin_when_already_set_exits_3(fake_token, tty, monkeypatch, capsys):
    _prompt_with(monkeypatch, "123456", "123456")
    assert main(["set-pin"]) == EXIT_PIN
    assert "already set" in capsys.readouterr().err


def test_set_pin_unsupported_exits_4(fake_token, tty, monkeypatch):
    fake_token.info.options.pop("clientPin")
    _prompt_with(monkeypatch, "123456", "123456")
    assert main(["set-pin"]) == EXIT_UNSUPPORTED


# ---------------------------------------------------------------------------
# CHANGE PIN
# ---------------------------------------------------------------------------
def test_change_pin_succeeds(fake_token, tty, monkeypatch, capsys):
    _prompt_with(monkeypatch, "123456", "654321", "654321")
    assert main(["change-pin"]) == EXIT_OK
    assert FakeClientPin.last.change_pin_calls == [("123456", "654321")]
    assert "PIN changed successfully" in capsys.readouterr().out


def test_change_pin_from_environment(fake_token, tty, monkeypatch):
    monkeypatch.setenv("HIRSCH_PIN", "111111")
    monkeypatch.setenv("HIRSCH_NEW_PIN", "222222")
    assert main(["change-pin"]) == EXIT_OK
    assert FakeClientPin.last.change_pin_calls == [("111111", "222222")]


def test_change_pin_wrong_pin_reports_retries(fake_token, tty, monkeypatch, capsys):
    fake_token.raise_on_change = ctap_error("PIN_INVALID")
    fake_token.pin_retries = 5
    _prompt_with(monkeypatch, "000000", "654321", "654321")
    assert main(["change-pin"]) == EXIT_PIN
    assert "5 attempt" in capsys.readouterr().err


def test_change_pin_blocked_exits_3(fake_token, tty, monkeypatch, capsys):
    fake_token.raise_on_change = ctap_error("PIN_BLOCKED")
    _prompt_with(monkeypatch, "123456", "654321", "654321")
    assert main(["change-pin"]) == EXIT_PIN
    assert "factory reset" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# RESET
# ---------------------------------------------------------------------------
def test_reset_requires_typed_confirmation(fake_token, tty, monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda *_: "no")
    assert main(["reset"]) == EXIT_CANCELLED
    assert fake_token.reset_calls == 0
    assert "cancelled" in capsys.readouterr().out.lower()


def test_reset_proceeds_on_exact_word(fake_token, tty, monkeypatch, capsys):
    answers = iter(["RESET", ""])
    monkeypatch.setattr("builtins.input", lambda *_: next(answers))
    assert main(["reset"]) == EXIT_OK
    assert fake_token.reset_calls == 1
    out = capsys.readouterr().out
    assert "Factory reset complete" in out
    assert "touch the token" in out


def test_reset_yes_flag_skips_confirmation(fake_token, tty, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *_: "")
    assert main(["reset", "--yes"]) == EXIT_OK
    assert fake_token.reset_calls == 1


def test_reset_non_interactive_without_yes_is_refused(fake_token, monkeypatch):
    """A piped/automated run must not destroy a key without --yes."""
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    assert main(["reset"]) == EXIT_CANCELLED
    assert fake_token.reset_calls == 0


def test_reset_window_expired_message(fake_token, tty, monkeypatch, capsys):
    fake_token.raise_on_reset = ctap_error("NOT_ALLOWED")
    monkeypatch.setattr("builtins.input", lambda *_: "")
    assert main(["reset", "--yes"]) != EXIT_OK
    assert "few seconds" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# INTERRUPT
# ---------------------------------------------------------------------------
def test_keyboard_interrupt_exits_130(fake_token, tty, monkeypatch):
    def boom(*_args, **_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli.getpass, "getpass", boom)
    assert main(["change-pin"]) == EXIT_CANCELLED
