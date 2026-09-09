# Hirsch SecureFIDO Device Config

Command-line device configuration for Hirsch SecureKey / SecureKey GOV FIDO2
authenticators on macOS.

This is the **device configuration subset** of the Windows
*Hirsch SecureFIDO Cred Manager*. It provides exactly four operations:

| Command | Description | Origin |
| --- | --- | --- |
| `info` | Read authenticator info: AAGUID, versions, options, limits, PIN retries | ported from the Windows app |
| `set-pin` | Set the initial PIN on a factory-fresh token | new |
| `change-pin` | Change an existing PIN | new |
| `reset` | Factory reset: erase all credentials and clear the PIN | new |

Only the device-info view existed in the Windows original. It read
authenticator info and rendered the AAGUID, versions, options, and limits;
that logic, including the option labels and COSE algorithm names, is carried
over here. The Windows app could *report* on the PIN (retry count, whether one
was set) and could surface PIN errors, but it had no way to set, change, or
clear one: it only ever called `getPinToken` to authenticate credential
management. Set PIN, Change PIN, and Factory Reset are therefore newly
implemented against CTAP `authenticatorClientPIN` and `authenticatorReset`.

Credential enumeration and deletion, which were the Windows app's main
purpose, are intentionally **not** included.

## Install

### Homebrew

```bash
brew tap hirschsecure/tap
brew install hirsch-securefido
```

### PyPI

```bash
pip install hirsch-securefido

# with NFC / CCID reader support
pip install "hirsch-securefido[pcsc]"
```

## Usage

```bash
hirsch-securefido info              # human-readable device report
hirsch-securefido info --json       # machine-readable, for MDM tooling
hirsch-securefido list              # enumerate connected authenticators

hirsch-securefido set-pin           # prompts for a new PIN, twice
hirsch-securefido change-pin        # prompts for current then new PIN
hirsch-securefido reset             # requires typing RESET, then a touch
```

By default only Hirsch authenticators (USB Vendor ID `04E6`) are accepted.
Pass `--any-vendor` to work with other FIDO2 keys.

### Unattended use

PINs may be supplied by environment variable for provisioning scripts:

```bash
HIRSCH_PIN=oldpin HIRSCH_NEW_PIN=newpin hirsch-securefido change-pin
hirsch-securefido reset --yes
```

PINs are also read from stdin when it is not a TTY:

```bash
echo "123456" | hirsch-securefido set-pin
```

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | General device error |
| `2` | No authenticator found |
| `3` | PIN rejected or blocked |
| `4` | Operation unsupported by the token |
| `130` | Cancelled by the user |

## Factory reset

CTAP requires a factory reset to arrive within a few seconds of the token
powering up, confirmed by a physical touch. The `reset` command therefore
prompts you to unplug and re-insert the token first. If you see
"a factory reset must be started within a few seconds", re-insert the key and
run the command again promptly.

A reset destroys every passkey on the device and clears the PIN. You will lose
access to any account that relies on this key as its only factor.

## macOS notes

The Windows original auto-elevated to Administrator, because non-elevated
Windows processes cannot open FIDO HID authenticators. macOS grants HID access
to the console user, so **no `sudo` is required**. The Windows-only
`winscard.dll` / `cfgmgr32.dll` hardware gate and disconnect watchdog have been
replaced by a direct USB Vendor ID check on the CTAP HID descriptor.

`pyscard` is optional. Install the `pcsc` extra only if you need NFC or
smart-card readers; it requires the PCSC-Lite build toolchain.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src tests
```

The test suite runs entirely against software authenticators, so no hardware is
needed. It has two layers:

- `tests/test_device.py`, `tests/test_cli.py` stub out `fido2` to test error
  handling and CLI behavior in isolation.
- `tests/test_integration.py` runs the **real** python-fido2 stack (CBOR, ECDH
  key agreement, AES-CBC PIN encryption, HMAC `pinUvAuthParam`) against the
  virtual authenticator in `tests/virtual_authenticator.py`, then asserts on
  the resulting device state.

To confirm the suite actually detects bugs rather than passing vacuously:

```bash
python scripts/mutation_check.py
```

This injects plausible defects (swapped PIN arguments, a skipped guard, a reset
that never fires) and requires the suite to fail on each one.

### What software cannot verify

USB HID transport, the CTAP reset power-up window, and the physical touch
confirmation have no software equivalent. `brew install` likewise needs macOS.
These are covered by the manual hardware checklist in
[PUBLISHING.md](PUBLISHING.md).

## License

BSD 3-Clause. See [LICENSE](LICENSE).
