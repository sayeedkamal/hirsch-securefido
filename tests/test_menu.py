"""
Tests for the interactive menu.

The menu must never appear for a scripted invocation: a piped stdin means
nobody can answer a prompt, so blocking there would hang CI and provisioning
runs forever. That property is asserted first because it is the one that
breaks automation.
"""

from __future__ import annotations

import pytest

from hirsch_securefido import cli, menu
from hirsch_securefido.cli import EXIT_NO_DEVICE, EXIT_OK, main


@pytest.fixture(autouse=True)
def no_color(monkeypatch):
    monkeypatch.setattr(cli.ST, "enabled", False)


@pytest.fixture
def tty(monkeypatch):
    """
    Pretend the process is attached to a terminal.

    pytest's capsys swaps sys.stdout for a capture object, so patching
    isatty on the live stream does not survive. Gating is asserted directly
    in the should_show_menu tests below; here we force the menu on so the
    rendering and navigation paths can be exercised under capture.
    """
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli, "should_show_menu", lambda argv: not argv)


def _answers(monkeypatch, *responses):
    queue = list(responses)
    monkeypatch.setattr("builtins.input", lambda *_a: queue.pop(0))


# ---------------------------------------------------------------------------
# GATING - the property that protects automation
# ---------------------------------------------------------------------------
def test_menu_is_hidden_when_stdin_is_piped(monkeypatch):
    monkeypatch.setattr(menu.sys.stdin, "isatty", lambda: False)
    assert menu.should_show_menu([]) is False


def test_menu_is_hidden_when_stdout_is_redirected(monkeypatch):
    monkeypatch.setattr(menu.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(menu.sys.stdout, "isatty", lambda: False)
    assert menu.should_show_menu([]) is False


def test_menu_is_hidden_when_arguments_are_given(monkeypatch):
    monkeypatch.setattr(menu.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(menu.sys.stdout, "isatty", lambda: True)
    assert menu.should_show_menu(["info"]) is False
    assert menu.should_show_menu(["--version"]) is False


def test_menu_shows_for_a_bare_interactive_call(monkeypatch):
    monkeypatch.setattr(menu.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(menu.sys.stdout, "isatty", lambda: True)
    assert menu.should_show_menu([]) is True


def test_piped_bare_invocation_still_prints_help(monkeypatch, capsys):
    """The pre-menu behaviour must survive for scripts."""
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(menu.sys.stdin, "isatty", lambda: False)
    assert main([]) == EXIT_OK
    assert "usage:" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# RENDERING
# ---------------------------------------------------------------------------
def test_menu_lists_the_four_operations(fake_token, tty, monkeypatch, capsys):
    _answers(monkeypatch, "q")
    main([])
    out = capsys.readouterr().out
    for label in ("Device information", "Set PIN", "Change PIN", "Factory reset"):
        assert label in out
    assert "Quit" in out


def test_header_reports_a_connected_token(fake_token, tty, monkeypatch, capsys):
    _answers(monkeypatch, "q")
    main([])
    out = capsys.readouterr().out
    assert "Hirsch SecureKey" in out
    assert "PIN set" in out


def test_header_reports_a_missing_token(no_token, tty, monkeypatch, capsys):
    _answers(monkeypatch, "q")
    main([])
    assert "No authenticator detected" in capsys.readouterr().out


def test_header_flags_a_token_with_no_pin(fake_token, tty, monkeypatch, capsys):
    fake_token.info.options["clientPin"] = False
    _answers(monkeypatch, "q")
    main([])
    assert "no PIN set" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# NAVIGATION
# ---------------------------------------------------------------------------
def test_quit_returns_zero(fake_token, tty, monkeypatch):
    _answers(monkeypatch, "q")
    assert main([]) == EXIT_OK


def test_selecting_info_runs_the_real_command(fake_token, tty, monkeypatch, capsys):
    _answers(monkeypatch, "1", "", "q")
    main([])
    out = capsys.readouterr().out
    # The genuine info renderer ran, not a menu-only stub.
    assert "00010203-0405-0607-0809-0a0b0c0d0e0f" in out
    assert "SUPPORTED ALGORITHMS" in out


def test_invalid_choice_is_rejected_without_exiting(fake_token, tty, monkeypatch, capsys):
    _answers(monkeypatch, "99", "", "q")
    assert main([]) == EXIT_OK
    assert "Not an option" in capsys.readouterr().out


def test_refresh_redraws_the_menu(fake_token, tty, monkeypatch, capsys):
    _answers(monkeypatch, "r", "q")
    main([])
    # Header drawn twice: once initially, once after the refresh.
    assert capsys.readouterr().out.count("Device information") == 2


def test_menu_survives_a_failing_command(no_token, tty, monkeypatch, capsys):
    """A device error must return to the menu, not crash out of it."""
    _answers(monkeypatch, "1", "", "q")
    assert main([]) == EXIT_NO_DEVICE
    captured = capsys.readouterr()
    assert "No Hirsch FIDO2 token found" in captured.err
    assert captured.out.count("Device information") == 2


def test_eof_at_the_prompt_exits_cleanly(fake_token, tty, monkeypatch):
    def raise_eof(*_a):
        raise EOFError

    monkeypatch.setattr("builtins.input", raise_eof)
    assert main([]) == EXIT_OK


def test_ctrl_c_at_the_prompt_exits_cleanly(fake_token, tty, monkeypatch):
    def raise_interrupt(*_a):
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", raise_interrupt)
    assert main([]) == EXIT_OK


# ---------------------------------------------------------------------------
# SAFETY - destructive actions keep their guards
# ---------------------------------------------------------------------------
def test_reset_from_the_menu_still_requires_typing_RESET(
    fake_token, tty, monkeypatch, capsys
):
    # "4" selects reset, "no" declines the typed confirmation.
    _answers(monkeypatch, "4", "no", "", "q")
    main([])
    assert fake_token.reset_calls == 0
    assert "cancelled" in capsys.readouterr().out.lower()


def test_reset_from_the_menu_proceeds_on_the_exact_word(
    fake_token, tty, monkeypatch
):
    _answers(monkeypatch, "4", "RESET", "", "", "q")
    main([])
    assert fake_token.reset_calls == 1
