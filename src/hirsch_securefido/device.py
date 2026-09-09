# ---------------------------------------------------------------------------
# Copyright (c) 2026, Hirsch Secure, Inc.
# All rights reserved.
# ---------------------------------------------------------------------------
"""
Device configuration layer (CTAP 2.x, python-fido2).

Provenance
----------
Only `get_device_info` is a port: the Windows Cred Manager's device-details
view (`get_device_status` / `_render_details`) supplied the option labels,
COSE algorithm names, and the fields reported here.

`set_pin`, `change_pin`, and `factory_reset` are NEW. The Windows app could
report the PIN retry count and surface PIN errors, but it never set, changed,
or cleared a PIN; it only called getPinToken to authenticate credential
management. These three are implemented against CTAP authenticatorClientPIN
(setPIN / changePIN) and authenticatorReset.

All credential-management code (getCredsMetadata / enumerateRPs /
enumerateCredentials / deleteCredential), which was the original app's main
purpose, has been dropped.

macOS notes
-----------
  * No Administrator auto-elevation. On Windows, non-elevated processes cannot
    open FIDO HID authenticators; macOS grants HID access to the console user,
    so the elevation gate in the original app is neither needed nor portable.
  * No winscard.dll / cfgmgr32.dll hardware gate or disconnect watchdog. Those
    are Windows Setup-API concepts. Hardware selection here is done directly on
    the CTAP HID device descriptor's USB Vendor ID, which is the part of the
    original check that is actually meaningful cross-platform.
  * PC/SC is optional. `pyscard` is not a hard dependency because a Homebrew
    install should not require the PCSC-Lite build toolchain; if it is present,
    NFC/CCID readers are used as a fallback exactly as on Windows.

HID is probed before PC/SC, preserving the original ordering. Composite keys
(uTrust FIDO2, VID 04E6 / PID 5A11) expose a CCID face and a CTAP HID face over
one secure element; merely opening the CCID face can schedule a deferred card
unpower that resets the shared SE mid-session. Probing HID first means the CCID
face is never touched when a HID key is present.
"""

from __future__ import annotations

import platform
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, Ctap2
from fido2.hid import CtapHidDevice

try:  # optional: NFC / CCID readers via pyscard
    from fido2.pcsc import CtapPcscDevice

    HAVE_PCSC = True
except Exception:  # pragma: no cover - depends on optional pyscard install
    CtapPcscDevice = None  # type: ignore[assignment]
    HAVE_PCSC = False


# ---------------------------------------------------------------------------
# HARDWARE ALLOW-LIST
# ---------------------------------------------------------------------------
HIRSCH_VID = 0x04E6  # SCM / Identiv / Hirsch USB Vendor ID
ALLOWED_HID_VIDS: tuple[int, ...] = (HIRSCH_VID,)

PROTOCOL_TIMEOUT = 120  # seconds; user-presence taps are slow


# ---------------------------------------------------------------------------
# ERRORS
# ---------------------------------------------------------------------------
class DeviceError(Exception):
    """Base error for all device-configuration failures."""


class DeviceNotFoundError(DeviceError):
    """No approved Hirsch authenticator is connected."""


class PinError(DeviceError):
    """The PIN was rejected or violates a policy."""

    def __init__(self, message: str, retries: int | None = None):
        super().__init__(message)
        self.retries = retries


class PinBlockedError(DeviceError):
    """PIN retries are exhausted; the token needs a re-seat or factory reset."""


class UnsupportedOperationError(DeviceError):
    """The connected token does not implement the requested operation."""


class ResetNotAllowedError(DeviceError):
    """The reset window expired or the user declined the presence check."""


# ---------------------------------------------------------------------------
# HUMAN-READABLE MAPS (kept from the original UI layer)
# ---------------------------------------------------------------------------
ALG_NAMES = {
    -7: "ES256",
    -8: "EdDSA",
    -35: "ES384",
    -36: "ES512",
    -47: "ES256K",
    -257: "RS256",
}

OPTION_LABELS: list[tuple[str, str]] = [
    ("rk", "Resident Keys"),
    ("up", "User Presence"),
    ("uv", "User Verification"),
    ("plat", "Platform Authenticator"),
    ("alwaysUv", "Always Require User Verification"),
    ("credMgmt", "Credential Management"),
    ("authnrCfg", "Authenticator Config"),
    ("clientPin", "Client PIN"),
    ("largeBlobs", "Large Blobs"),
    ("pinUvAuthToken", "PIN/UV Auth Token"),
    ("setMinPINLength", "Set Minimum PIN Length"),
    ("makeCredUvNotRqd", "Make Credential Without UV"),
]


# ---------------------------------------------------------------------------
# DATA MODEL
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class DeviceInfo:
    """A flattened, presentation-ready snapshot of authenticator info."""

    transport: str
    product: str | None
    aaguid: str
    versions: tuple[str, ...]
    extensions: tuple[str, ...]
    options: dict[str, bool]
    algorithms: tuple[str, ...]
    pin_set: bool
    pin_retries: int | None
    force_pin_change: bool
    min_pin_length: int | None
    max_msg_size: int | None
    max_creds_in_list: int | None
    max_cred_id_length: int | None
    pin_uv_protocols: tuple[int, ...]
    firmware_version: int | None
    remaining_disc_creds: int | None
    raw_options: dict[str, bool] = field(default_factory=dict, repr=False)

    @property
    def option_rows(self) -> list[tuple[str, bool]]:
        """(label, value) pairs for the options the token actually reports."""
        return [
            (label, bool(self.options[key]))
            for key, label in OPTION_LABELS
            if key in self.options
        ]

    def as_dict(self) -> dict[str, Any]:
        """JSON-serialisable form (used by `--json`)."""
        return {
            "transport": self.transport,
            "product": self.product,
            "aaguid": self.aaguid,
            "versions": list(self.versions),
            "extensions": list(self.extensions),
            "options": dict(self.options),
            "algorithms": list(self.algorithms),
            "pin_set": self.pin_set,
            "pin_retries": self.pin_retries,
            "force_pin_change": self.force_pin_change,
            "min_pin_length": self.min_pin_length,
            "max_msg_size": self.max_msg_size,
            "max_creds_in_list": self.max_creds_in_list,
            "max_cred_id_length": self.max_cred_id_length,
            "pin_uv_protocols": list(self.pin_uv_protocols),
            "firmware_version": self.firmware_version,
            "remaining_disc_creds": self.remaining_disc_creds,
        }


# ---------------------------------------------------------------------------
# DISCOVERY
# ---------------------------------------------------------------------------
def _hid_candidates(any_vendor: bool) -> list[tuple[Any, str, str | None]]:
    out: list[tuple[Any, str, str | None]] = []
    try:
        devices = list(CtapHidDevice.list_devices())
    except Exception:
        return out
    for dev in devices:
        desc = getattr(dev, "descriptor", None)
        vid = getattr(desc, "vid", None)
        product = getattr(desc, "product_name", None)
        if any_vendor or vid in ALLOWED_HID_VIDS:
            label = f"USB HID (VID {vid:04X})" if isinstance(vid, int) else "USB HID"
            out.append((dev, label, product))
        else:
            try:
                dev.close()
            except Exception:
                pass
    return out


def _pcsc_candidates() -> list[tuple[Any, str, str | None]]:
    if not HAVE_PCSC:
        return []
    out: list[tuple[Any, str, str | None]] = []
    try:
        for dev in CtapPcscDevice.list_devices():
            name = getattr(dev, "_name", None) or "reader"
            out.append((dev, f"PC/SC ({name})", name))
    except Exception:
        pass
    return out


def get_fido_candidates(any_vendor: bool = False) -> list[tuple[Any, str, str | None]]:
    """
    Collect candidate CTAP devices, HID first, then PC/SC.

    Returns a list of (device, transport_label, product_name). PC/SC is only
    consulted when no HID candidate was found, so a composite key's CCID face
    is never opened while its HID face is usable.
    """
    candidates = _hid_candidates(any_vendor)
    if not candidates:
        candidates = _pcsc_candidates()
    return candidates


def list_devices(any_vendor: bool = False) -> list[tuple[str, str | None]]:
    """Enumerate connected authenticators as (transport_label, product)."""
    found: list[tuple[str, str | None]] = []
    for dev, label, product in get_fido_candidates(any_vendor):
        found.append((label, product))
        try:
            dev.close()
        except Exception:
            pass
    return found


class _OpenDevice:
    """Context manager yielding (Ctap2, transport_label, product)."""

    def __init__(self, any_vendor: bool = False):
        self._any_vendor = any_vendor
        self._dev: Any = None

    def __enter__(self) -> tuple[Ctap2, str, str | None]:
        candidates = get_fido_candidates(self._any_vendor)
        if not candidates:
            raise DeviceNotFoundError(
                "No Hirsch FIDO2 token found. Insert an approved USB key, or "
                "seat the card on a reader.\n"
                "If you are using a non-Hirsch authenticator, pass --any-vendor."
            )
        skipped: list[str] = []
        for dev, label, product in candidates:
            try:
                ctap2 = Ctap2(dev)
            except Exception as exc:
                skipped.append(f"{label}: {exc}")
                try:
                    dev.close()
                except Exception:
                    pass
                continue
            self._dev = dev
            return ctap2, label, product
        detail = ("\n" + "\n".join(skipped)) if skipped else ""
        raise DeviceNotFoundError("No CTAP2-capable Hirsch token found." + detail)

    def __exit__(self, *exc_info) -> None:
        if self._dev is not None:
            try:
                self._dev.close()
            except Exception:
                pass
            self._dev = None


def _pin_retries(ctap2: Ctap2) -> int | None:
    try:
        return ClientPin(ctap2).get_pin_retries()[0]
    except Exception:
        return None


def _translate_ctap_error(exc: CtapError, ctap2: Ctap2 | None = None) -> DeviceError:
    """Map a raw CTAP status byte onto an actionable, user-facing error."""
    code = exc.code
    err = CtapError.ERR
    retries = _pin_retries(ctap2) if ctap2 is not None else None

    if code == err.PIN_INVALID:
        suffix = f" {retries} attempt(s) remaining." if retries is not None else ""
        return PinError("Incorrect PIN." + suffix, retries)
    if code == err.PIN_AUTH_BLOCKED:
        return PinBlockedError(
            "PIN authentication is blocked. Remove and re-insert the token, "
            "then try again."
        )
    if code == err.PIN_BLOCKED:
        return PinBlockedError(
            "PIN is permanently blocked. A factory reset is required "
            "(this destroys all credentials)."
        )
    if code == err.PIN_POLICY_VIOLATION:
        return PinError(
            "The new PIN violates the token's PIN policy (too short, too "
            "simple, or too long)."
        )
    if code == err.PIN_NOT_SET:
        return PinError("No PIN is set on this token. Use `set-pin` first.")
    if code == err.PIN_AUTH_INVALID:
        return PinError(
            "PIN authentication failed. Re-seat the token and try again."
        )
    if code == err.NOT_ALLOWED:
        return ResetNotAllowedError(
            "The token refused the operation. A factory reset must be started "
            "within a few seconds of inserting the token."
        )
    if code == err.ACTION_TIMEOUT or code == err.USER_ACTION_TIMEOUT:
        return ResetNotAllowedError(
            "Timed out waiting for you to touch the token."
        )
    if code == err.OPERATION_DENIED:
        return ResetNotAllowedError("The operation was declined on the token.")
    if code == err.INVALID_COMMAND or code == err.UNSUPPORTED_OPTION:
        return UnsupportedOperationError(
            "This token does not support the requested operation."
        )
    return DeviceError(f"Token returned CTAP error 0x{code:02X}: {exc}")


# ---------------------------------------------------------------------------
# OPERATION 1 - DEVICE INFO
# ---------------------------------------------------------------------------
def get_device_info(any_vendor: bool = False) -> DeviceInfo:
    """Read authenticator info. Requires no PIN and no user presence."""
    with _OpenDevice(any_vendor) as (ctap2, transport, product):
        info = ctap2.info
        options = dict(info.options or {})
        pin_set = bool(options.get("clientPin"))
        retries = _pin_retries(ctap2) if "clientPin" in options else None

        raw = info.aaguid.hex()
        aaguid = f"{raw[:8]}-{raw[8:12]}-{raw[12:16]}-{raw[16:20]}-{raw[20:]}"

        algorithms: tuple[str, ...] = ()
        if info.algorithms:
            algorithms = tuple(
                ALG_NAMES.get(a.get("alg"), str(a.get("alg")))
                for a in info.algorithms
            )

        return DeviceInfo(
            transport=transport,
            product=product,
            aaguid=aaguid,
            versions=tuple(info.versions or ()),
            extensions=tuple(info.extensions or ()),
            options=options,
            algorithms=algorithms,
            pin_set=pin_set,
            pin_retries=retries,
            force_pin_change=bool(getattr(info, "force_pin_change", False)),
            min_pin_length=info.min_pin_length,
            max_msg_size=info.max_msg_size,
            max_creds_in_list=info.max_creds_in_list,
            max_cred_id_length=info.max_cred_id_length,
            pin_uv_protocols=tuple(info.pin_uv_protocols or ()),
            firmware_version=info.firmware_version,
            remaining_disc_creds=getattr(info, "remaining_disc_creds", None),
            raw_options=options,
        )


# ---------------------------------------------------------------------------
# OPERATION 2 - SET PIN
# ---------------------------------------------------------------------------
def set_pin(new_pin: str, any_vendor: bool = False) -> None:
    """
    Set the initial PIN on a token that has none.

    Refuses up front when a PIN already exists, because CTAP reports that
    condition as a bare PIN_AUTH_INVALID which reads as "the tool is broken"
    rather than "use change-pin".
    """
    with _OpenDevice(any_vendor) as (ctap2, _transport, _product):
        options = dict(ctap2.info.options or {})
        if "clientPin" not in options:
            raise UnsupportedOperationError(
                "This token does not support a client PIN."
            )
        if options.get("clientPin"):
            raise PinError(
                "A PIN is already set on this token. Use `change-pin` to "
                "change it, or `reset` to clear it (destroys credentials)."
            )
        _validate_pin_length(new_pin, ctap2.info)
        try:
            ClientPin(ctap2).set_pin(new_pin)
        except CtapError as exc:
            raise _translate_ctap_error(exc, ctap2) from exc


# ---------------------------------------------------------------------------
# OPERATION 3 - CHANGE PIN
# ---------------------------------------------------------------------------
def change_pin(old_pin: str, new_pin: str, any_vendor: bool = False) -> None:
    """Change an existing PIN. Costs one PIN retry if `old_pin` is wrong."""
    with _OpenDevice(any_vendor) as (ctap2, _transport, _product):
        options = dict(ctap2.info.options or {})
        if "clientPin" not in options:
            raise UnsupportedOperationError(
                "This token does not support a client PIN."
            )
        if not options.get("clientPin"):
            raise PinError(
                "No PIN is set on this token. Use `set-pin` to set one first."
            )
        _validate_pin_length(new_pin, ctap2.info)
        if old_pin == new_pin:
            raise PinError("The new PIN must differ from the current PIN.")
        try:
            ClientPin(ctap2).change_pin(old_pin, new_pin)
        except CtapError as exc:
            raise _translate_ctap_error(exc, ctap2) from exc


def _validate_pin_length(pin: str, info: Any) -> None:
    """
    Client-side length check against the token's reported policy.

    CTAP measures the PIN in UTF-8 bytes, not characters, so a 4-character
    PIN of non-ASCII glyphs can still be a valid 8-byte PIN. Checking bytes
    here matches what the authenticator will enforce.
    """
    encoded = pin.encode("utf-8")
    minimum = getattr(info, "min_pin_length", None) or 4
    maximum = getattr(info, "max_pin_length", None) or 63
    if len(encoded) < minimum:
        raise PinError(
            f"PIN is too short: this token requires at least {minimum} "
            f"characters (got {len(encoded)})."
        )
    if len(encoded) > maximum:
        raise PinError(
            f"PIN is too long: maximum {maximum} characters (got {len(encoded)})."
        )


# ---------------------------------------------------------------------------
# OPERATION 4 - FACTORY RESET
# ---------------------------------------------------------------------------
def factory_reset(
    any_vendor: bool = False,
    on_keepalive: Callable[[int], None] | None = None,
    timeout: int = PROTOCOL_TIMEOUT,
) -> None:
    """
    Factory reset the authenticator.

    Destroys every discoverable credential and clears the PIN. CTAP requires
    the reset to arrive within a short window (typically 10 s) of power-up,
    and to be confirmed by a physical touch, so the caller should prompt the
    user to re-insert the token first.
    """
    # python-fido2 cancels a pending request when this threading.Event is set,
    # which is how the timeout below unblocks a token that is never touched.
    event = threading.Event()
    timer = threading.Timer(timeout, event.set)
    timer.daemon = True
    timer.start()
    try:
        with _OpenDevice(any_vendor) as (ctap2, _transport, _product):
            try:
                ctap2.reset(event=event, on_keepalive=on_keepalive)
            except CtapError as exc:
                raise _translate_ctap_error(exc, None) from exc
            except Exception as exc:
                if event.is_set():
                    raise ResetNotAllowedError(
                        "Timed out waiting for the touch confirmation."
                    ) from exc
                raise DeviceError(f"Factory reset failed: {exc}") from exc
    finally:
        timer.cancel()


# ---------------------------------------------------------------------------
# PLATFORM
# ---------------------------------------------------------------------------
def platform_summary() -> str:
    return f"{platform.system()} {platform.release()} ({platform.machine()})"
