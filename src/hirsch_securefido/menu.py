# ---------------------------------------------------------------------------
# Copyright (c) 2026, Hirsch Secure, Inc.
# All rights reserved.
# ---------------------------------------------------------------------------
"""
Interactive menu shown when the tool is launched with no arguments.

Design constraints:

  * Only ever runs on a TTY. A piped or scripted invocation must keep the
    old non-interactive behaviour, or provisioning scripts would hang
    forever waiting on a prompt that nobody can answer.
  * Live device status in the header, refreshed after every action, so the
    operator can see the token was detected before choosing an operation.
  * Destructive actions keep every guard from the subcommand path: factory
    reset still requires typing RESET and re-inserting the token.
"""

from __future__ import annotations

import sys
from collections.abc import Callable

from . import __app_name__, __version__
from .device import DeviceError, get_device_info

MENU_ITEMS: list[tuple[str, str, str]] = [
    ("1", "info", "Device information"),
    ("2", "set-pin", "Set PIN"),
    ("3", "change-pin", "Change PIN"),
    ("4", "reset", "Factory reset"),
]


def _status_line(style, any_vendor: bool) -> str:
    """One-line device summary for the menu header."""
    try:
        info = get_device_info(any_vendor=any_vendor)
    except DeviceError:
        return style.yellow("No authenticator detected")

    name = info.product or "FIDO2 authenticator"
    bits = [style.green(name), style.dim(info.transport)]
    if info.pin_set:
        retries = (
            f", {info.pin_retries} attempt(s) left"
            if info.pin_retries is not None
            else ""
        )
        bits.append(f"PIN set{retries}")
    else:
        bits.append(style.yellow("no PIN set"))
    return "  ".join(bits)


def _render(style, any_vendor: bool) -> None:
    width = 56
    print()
    print("  " + style.bold(style.cyan(__app_name__)) + style.dim(f"  v{__version__}"))
    print("  " + style.dim("-" * width))
    print("  " + _status_line(style, any_vendor))
    print("  " + style.dim("-" * width))
    print()
    for key, _command, label in MENU_ITEMS:
        print(f"    {style.bold(key)}  {label}")
    print(f"    {style.bold('r')}  Refresh device status")
    print(f"    {style.bold('q')}  Quit")
    print()


def run_menu(
    dispatch: Callable[[str], int],
    style,
    any_vendor: bool = False,
) -> int:
    """
    Loop until the operator quits.

    `dispatch` runs one named command and returns its exit code; the menu
    reuses the exact subcommand implementations so behaviour cannot drift
    between the two entry points.
    """
    by_key = {key: command for key, command, _ in MENU_ITEMS}
    last_code = 0

    while True:
        _render(style, any_vendor)
        try:
            choice = input("  Select an option: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return last_code

        if choice in ("q", "quit", "exit"):
            return last_code
        if choice in ("r", "refresh", ""):
            continue

        command = by_key.get(choice)
        if command is None:
            print(f"  {style.yellow('Not an option:')} {choice!r}")
            _pause(style)
            continue

        try:
            last_code = dispatch(command)
        except KeyboardInterrupt:
            print()
            print(f"  {style.yellow('Cancelled.')}")
            last_code = 130
        _pause(style)


def _pause(style) -> None:
    try:
        input(f"  {style.dim('Press Enter to return to the menu...')}")
    except (EOFError, KeyboardInterrupt):
        print()
        raise SystemExit(0) from None


def should_show_menu(argv: list[str]) -> bool:
    """
    The menu appears only for a bare, interactive invocation.

    A piped stdin means a script is driving the tool, so it must fall back
    to printing help and exiting rather than blocking on input.
    """
    if argv:
        return False
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        return False
    return True
