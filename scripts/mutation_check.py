#!/usr/bin/env python3
"""
Mutation check for the device-configuration layer.

Confirms the test suite has real diagnostic power: each mutation injects a
plausible bug, and the suite must fail. A mutation that SURVIVES means the
tests pass vacuously for that behavior.

    python scripts/mutation_check.py

Reads and writes bytes (not text) so it never rewrites line endings.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

SRC = pathlib.Path("src/hirsch_securefido/device.py")
SUITE = ["tests/test_integration.py", "tests/test_device.py"]

# (description, find, replace) - each is a bug a reviewer might plausibly ship.
MUTATIONS: list[tuple[str, bytes, bytes]] = [
    (
        "change_pin: swap old/new PIN arguments",
        b"ClientPin(ctap2).change_pin(old_pin, new_pin)",
        b"ClientPin(ctap2).change_pin(new_pin, old_pin)",
    ),
    (
        "set_pin: drop the already-set guard",
        b'if options.get("clientPin"):\n            raise PinError(',
        b"if False:\n            raise PinError(",
    ),
    (
        "factory_reset: never send the reset command",
        b"ctap2.reset(event=event, on_keepalive=on_keepalive)",
        b"pass  # mutated",
    ),
    (
        "info: invert pin_set",
        b'pin_set = bool(options.get("clientPin"))',
        b'pin_set = not bool(options.get("clientPin"))',
    ),
    (
        "discovery: leak the transport handle",
        b"self._dev.close()",
        b"pass  # mutated",
    ),
    (
        "change_pin: allow reusing the current PIN",
        b"if old_pin == new_pin:",
        b"if False:",
    ),
    (
        "vendor filter: accept any authenticator",
        b"if any_vendor or vid in ALLOWED_HID_VIDS:",
        b"if True:",
    ),
    (
        "PIN length: ignore the minimum policy",
        b"if len(encoded) < minimum:",
        b"if False:",
    ),
]


def main() -> int:
    original = SRC.read_bytes()
    results: list[tuple[str, str]] = []

    try:
        for name, find, replace in MUTATIONS:
            mutated = original.replace(find, replace)
            if mutated == original:
                results.append((name, "NOT APPLIED"))
                continue
            SRC.write_bytes(mutated)
            proc = subprocess.run(
                [sys.executable, "-m", "pytest", *SUITE, "-q", "-x"],
                capture_output=True,
                text=True,
            )
            results.append((name, "caught" if proc.returncode else "SURVIVED"))
            SRC.write_bytes(original)
    finally:
        SRC.write_bytes(original)

    print("\n=== MUTATION RESULTS ===")
    for name, status in results:
        marker = " " if status == "caught" else "!"
        print(f" {marker} {status:<12} {name}")

    missed = [n for n, s in results if s != "caught"]
    print(f"\n{len(results) - len(missed)}/{len(results)} mutations caught")
    if missed:
        print("\nUncaught mutations indicate untested behavior:")
        for name in missed:
            print(f"  - {name}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
