# ---------------------------------------------------------------------------
# Copyright (c) 2026, Hirsch Secure, Inc.
# All rights reserved.
# ---------------------------------------------------------------------------
"""
Command-line interface for the Hirsch SecureFIDO device-configuration tools.

    hirsch-securefido info
    hirsch-securefido set-pin
    hirsch-securefido change-pin
    hirsch-securefido reset
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from collections.abc import Sequence
from typing import Any

from . import __app_name__, __version__
from .device import (
    DeviceError,
    DeviceInfo,
    DeviceNotFoundError,
    PinBlockedError,
    PinError,
    ResetNotAllowedError,
    UnsupportedOperationError,
    change_pin,
    factory_reset,
    get_device_info,
    list_devices,
    platform_summary,
    set_pin,
)
from .menu import run_menu, should_show_menu

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_NO_DEVICE = 2
EXIT_PIN = 3
EXIT_UNSUPPORTED = 4
EXIT_CANCELLED = 130


# ---------------------------------------------------------------------------
# TERMINAL STYLING
# ---------------------------------------------------------------------------
class Style:
    """ANSI styling, disabled when not a TTY or when NO_COLOR is set."""

    def __init__(self, stream=sys.stdout):
        self.enabled = (
            hasattr(stream, "isatty")
            and stream.isatty()
            and os.environ.get("NO_COLOR") is None
            and os.environ.get("TERM") != "dumb"
        )

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def bold(self, t: str) -> str:
        return self._wrap("1", t)

    def dim(self, t: str) -> str:
        return self._wrap("2", t)

    def green(self, t: str) -> str:
        return self._wrap("32", t)

    def yellow(self, t: str) -> str:
        return self._wrap("33", t)

    def red(self, t: str) -> str:
        return self._wrap("31", t)

    def cyan(self, t: str) -> str:
        return self._wrap("36", t)


ST = Style()


def _supports_unicode(stream=None) -> bool:
    """
    Whether the output encoding can represent the box/status glyphs.

    A legacy Windows console (cp1252) or a redirected ASCII stream raises
    UnicodeEncodeError on '✓', which would crash the tool mid-operation
    after the PIN had already been changed on the token. Detect it and fall
    back to ASCII instead.
    """
    target = stream if stream is not None else sys.stdout
    encoding = getattr(target, "encoding", None) or ""
    try:
        "✓✗•→".encode(encoding or "ascii")
    except (UnicodeEncodeError, LookupError):
        return False
    return True


UNICODE_OK = _supports_unicode()

# (unicode, ascii) pairs, chosen so the ASCII fallback stays aligned.
GLYPH_OK = "✓" if UNICODE_OK else "+"
GLYPH_FAIL = "✗" if UNICODE_OK else "x"
GLYPH_WARN = "!"
GLYPH_BULLET = "•" if UNICODE_OK else "*"
GLYPH_ARROW = "→" if UNICODE_OK else "->"


def _out(msg: str = "") -> None:
    print(msg)


def _err(msg: str) -> None:
    print(msg, file=sys.stderr)


def _ok(msg: str) -> None:
    _out(f"{ST.green(GLYPH_OK)} {msg}")


def _warn(msg: str) -> None:
    _out(f"{ST.yellow(GLYPH_WARN)} {msg}")


def _fail(msg: str) -> None:
    _err(f"{ST.red(GLYPH_FAIL)} {msg}")


# ---------------------------------------------------------------------------
# INFO RENDERING
# ---------------------------------------------------------------------------
def _kv(label: str, value: Any, width: int = 30) -> None:
    _out(f"  {ST.dim(label.ljust(width))} {value}")


def _section(title: str) -> None:
    _out()
    _out(f"  {ST.bold(title.upper())}")


def render_info(info: DeviceInfo) -> None:
    _out()
    _out(f"  {ST.bold(ST.cyan(__app_name__))}  {ST.dim('v' + __version__)}")
    _out(f"  {ST.dim(platform_summary())}")

    _section("Device")
    _kv("Transport", info.transport)
    if info.product:
        _kv("Product", info.product)
    _kv("AAGUID", info.aaguid)
    if info.firmware_version is not None:
        _kv("Firmware Version", info.firmware_version)

    _section("PIN")
    _kv("PIN Set", "Yes" if info.pin_set else "No")
    if info.pin_retries is not None:
        # Highlight a nearly-exhausted retry counter: at 0 the token is
        # permanently blocked and only a factory reset recovers it.
        retries = str(info.pin_retries)
        _kv(
            "PIN Attempts Remaining",
            ST.red(retries) if info.pin_retries <= 2 else retries,
        )
    if info.min_pin_length is not None:
        _kv("Minimum PIN Length", info.min_pin_length)
    if info.force_pin_change:
        _kv("Force PIN Change", ST.yellow("Yes - PIN must be changed"))

    if info.versions:
        _section("Versions")
        _out("  " + ", ".join(info.versions))

    if info.extensions:
        _section("Extensions")
        _out("  " + ", ".join(info.extensions))

    rows = info.option_rows
    if rows:
        _section("Options")
        for label, value in rows:
            _kv(label, "Yes" if value else "No")

    if info.algorithms:
        _section("Supported Algorithms")
        _out("  " + ", ".join(info.algorithms))

    _section("Limits")
    for label, value in [
        ("Max Message Size", info.max_msg_size),
        ("Max Credentials in List", info.max_creds_in_list),
        ("Max Credential ID Length", info.max_cred_id_length),
        ("Remaining Credential Slots", info.remaining_disc_creds),
        (
            "PIN/UV Auth Protocols",
            ", ".join(str(p) for p in info.pin_uv_protocols) or None,
        ),
    ]:
        if value is not None:
            _kv(label, value)
    _out()


# ---------------------------------------------------------------------------
# PIN PROMPTING
# ---------------------------------------------------------------------------
def _read_pin(prompt: str, env_var: str | None = None) -> str:
    """
    Read a PIN from the environment, a non-TTY stdin pipe, or an echo-free
    prompt. The environment path exists so the tool can be driven from an MDM
    or provisioning script without a terminal.
    """
    if env_var:
        from_env = os.environ.get(env_var)
        if from_env:
            return from_env
    if not sys.stdin.isatty():
        line = sys.stdin.readline()
        if not line:
            raise DeviceError(f"No PIN supplied on stdin for: {prompt}")
        return line.rstrip("\n")
    return getpass.getpass(f"  {prompt}: ")


def _read_new_pin(confirm_prompt: str = "Confirm new PIN") -> str:
    new = _read_pin("New PIN", "HIRSCH_NEW_PIN")
    if os.environ.get("HIRSCH_NEW_PIN") or not sys.stdin.isatty():
        return new
    again = _read_pin(confirm_prompt)
    if new != again:
        raise PinError("The two PINs did not match. Nothing was changed.")
    return new


def _confirm(question: str, expect: str | None = None) -> bool:
    """Yes/no gate; `expect` demands an exact typed word for destructive acts."""
    if not sys.stdin.isatty():
        return False
    if expect:
        _out(f"  {question}")
        answer = input(f"  Type {ST.bold(expect)} to continue: ").strip()
        return answer == expect
    answer = input(f"  {question} [y/N]: ").strip().lower()
    return answer in ("y", "yes")


# ---------------------------------------------------------------------------
# COMMANDS
# ---------------------------------------------------------------------------
def cmd_info(args: argparse.Namespace) -> int:
    info = get_device_info(any_vendor=args.any_vendor)
    if args.json:
        print(json.dumps(info.as_dict(), indent=2))
    else:
        render_info(info)
    return EXIT_OK


def cmd_list(args: argparse.Namespace) -> int:
    devices = list_devices(any_vendor=args.any_vendor)
    if args.json:
        print(json.dumps([{"transport": t, "product": p} for t, p in devices], indent=2))
        return EXIT_OK if devices else EXIT_NO_DEVICE
    if not devices:
        _warn("No authenticators detected.")
        return EXIT_NO_DEVICE
    _out()
    for transport, product in devices:
        _out(f"  {ST.green(GLYPH_BULLET)} {transport}" + (f"  {ST.dim(product)}" if product else ""))
    _out()
    return EXIT_OK


def cmd_set_pin(args: argparse.Namespace) -> int:
    _out()
    _out(f"  {ST.bold('SET PIN')}")
    _out(f"  {ST.dim('Sets the initial PIN on a token that does not have one.')}")
    _out()
    new_pin = _read_new_pin()
    set_pin(new_pin, any_vendor=args.any_vendor)
    _out()
    _ok("PIN set successfully.")
    return EXIT_OK


def cmd_change_pin(args: argparse.Namespace) -> int:
    _out()
    _out(f"  {ST.bold('CHANGE PIN')}")
    _out(f"  {ST.dim('Changes the existing PIN on this token.')}")
    _out()
    old_pin = _read_pin("Current PIN", "HIRSCH_PIN")
    new_pin = _read_new_pin()
    change_pin(old_pin, new_pin, any_vendor=args.any_vendor)
    _out()
    _ok("PIN changed successfully.")
    return EXIT_OK


def cmd_reset(args: argparse.Namespace) -> int:
    _out()
    _out(f"  {ST.bold(ST.red('FACTORY RESET'))}")
    _out(
        f"  {ST.dim('This permanently erases every passkey on the token and')}"
    )
    _out(f"  {ST.dim('clears its PIN. This cannot be undone.')}")
    _out()

    if not args.yes:
        if not _confirm(
            "You will lose access to every account that uses this key.",
            expect="RESET",
        ):
            _warn("Factory reset cancelled. Nothing was changed.")
            return EXIT_CANCELLED

    _out()
    _out(f"  {ST.yellow('1.')} Unplug the token, then plug it back in now.")
    _out(f"  {ST.yellow('2.')} Touch the token when it blinks.")
    _out()
    if sys.stdin.isatty():
        input(f"  Press {ST.bold('Enter')} once the token is re-inserted... ")

    touched = {"seen": False}

    def on_keepalive(status: int) -> None:
        # CTAPHID status 2 = "waiting for user presence"
        if status == 2 and not touched["seen"]:
            touched["seen"] = True
            _out(f"  {ST.cyan(GLYPH_ARROW)} Waiting for you to touch the token...")

    factory_reset(any_vendor=args.any_vendor, on_keepalive=on_keepalive)
    _out()
    _ok("Factory reset complete. The token has no PIN and no credentials.")
    _out(f"  {ST.dim('Run `hirsch-securefido set-pin` to set a new PIN.')}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# ARGUMENT PARSING
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hirsch-securefido",
        description=(
            "Device configuration for Hirsch SecureKey / SecureKey GOV FIDO2 "
            "authenticators: device info, set PIN, change PIN, factory reset."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "environment variables:\n"
            "  HIRSCH_PIN       current PIN, for unattended use\n"
            "  HIRSCH_NEW_PIN   new PIN, for unattended use\n"
            "  NO_COLOR         disable ANSI colour output\n"
            "\n"
            "examples:\n"
            "  hirsch-securefido info\n"
            "  hirsch-securefido info --json\n"
            "  hirsch-securefido set-pin\n"
            "  hirsch-securefido change-pin\n"
            "  hirsch-securefido reset\n"
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--any-vendor",
        action="store_true",
        help="allow non-Hirsch authenticators (default: Hirsch VID 04E6 only)",
    )

    sub = parser.add_subparsers(dest="command", metavar="<command>")

    p_info = sub.add_parser("info", help="show device information")
    p_info.add_argument("--json", action="store_true", help="output raw JSON")
    p_info.set_defaults(func=cmd_info)

    p_list = sub.add_parser("list", help="list connected authenticators")
    p_list.add_argument("--json", action="store_true", help="output raw JSON")
    p_list.set_defaults(func=cmd_list)

    p_set = sub.add_parser("set-pin", help="set the initial PIN")
    p_set.set_defaults(func=cmd_set_pin)

    p_change = sub.add_parser("change-pin", help="change the existing PIN")
    p_change.set_defaults(func=cmd_change_pin)

    p_reset = sub.add_parser("reset", help="factory reset (destroys all data)")
    p_reset.add_argument(
        "--yes", action="store_true", help="skip the interactive confirmation"
    )
    p_reset.set_defaults(func=cmd_reset)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    raw_args = list(sys.argv[1:] if argv is None else argv)

    # A bare interactive invocation gets the menu; a bare piped invocation
    # keeps printing help, so scripts never block on a prompt.
    if should_show_menu(raw_args):
        return _run_interactive_menu(parser)

    args = parser.parse_args(raw_args)

    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_OK

    return _dispatch(args)


def _run_interactive_menu(parser: argparse.ArgumentParser) -> int:
    """Drive the menu, routing each choice back through the real subcommands."""

    def dispatch(command: str) -> int:
        # Re-parse through argparse so the menu path and the command-line
        # path execute identical code, including every default.
        return _dispatch(parser.parse_args([command]))

    try:
        return run_menu(dispatch, ST)
    except SystemExit as exc:
        return int(exc.code or EXIT_OK)


def _dispatch(args: argparse.Namespace) -> int:
    """Run one command, mapping device errors onto stable exit codes."""
    try:
        return args.func(args)
    except DeviceNotFoundError as exc:
        _fail(str(exc))
        return EXIT_NO_DEVICE
    except (PinError, PinBlockedError) as exc:
        _fail(str(exc))
        return EXIT_PIN
    except UnsupportedOperationError as exc:
        _fail(str(exc))
        return EXIT_UNSUPPORTED
    except ResetNotAllowedError as exc:
        _fail(str(exc))
        return EXIT_ERROR
    except DeviceError as exc:
        _fail(str(exc))
        return EXIT_ERROR
    except KeyboardInterrupt:
        _out()
        _warn("Cancelled.")
        return EXIT_CANCELLED


if __name__ == "__main__":
    sys.exit(main())
