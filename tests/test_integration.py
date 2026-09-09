"""
Integration tests against a virtual authenticator speaking real CTAP2 CBOR.

These complement tests/test_device.py: that file stubs out fido2 to test our
error handling in isolation, while this file runs the genuine python-fido2
`Ctap2` / `ClientPin` stack (ECDH, HKDF, AES-CBC, HMAC) over a virtual
transport, and asserts on the authenticator's resulting state.

If our code sends a malformed CTAP request, or python-fido2 changes its wire
format, these tests fail where the stubbed tests would still pass.
"""

from __future__ import annotations

import pytest
from virtual_authenticator import VirtualAuthenticator

from hirsch_securefido import device as dev_mod
from hirsch_securefido.device import (
    PinBlockedError,
    PinError,
    ResetNotAllowedError,
    change_pin,
    factory_reset,
    get_device_info,
    set_pin,
)


@pytest.fixture
def virtual(monkeypatch):
    """Install one virtual authenticator behind the real fido2 stack."""
    auth = VirtualAuthenticator()

    def candidates(any_vendor=False):
        return [(auth, "USB HID (VID 04E6)", "Hirsch SecureKey")]

    # Patch only discovery: Ctap2 and ClientPin remain the real classes.
    monkeypatch.setattr(dev_mod, "get_fido_candidates", candidates)
    return auth


# ---------------------------------------------------------------------------
# DEVICE INFO over real CBOR
# ---------------------------------------------------------------------------
def test_info_decodes_real_cbor_response(virtual):
    virtual.pin = "1234"
    info = get_device_info()
    assert info.aaguid == "00010203-0405-0607-0809-0a0b0c0d0e0f"
    assert info.pin_set is True
    assert info.pin_retries == 8
    assert "FIDO_2_1" in info.versions
    assert info.min_pin_length == 4
    assert info.firmware_version == 328966


def test_info_reports_no_pin_on_fresh_token(virtual):
    assert get_device_info().pin_set is False


# ---------------------------------------------------------------------------
# SET PIN through the real PIN protocol
# ---------------------------------------------------------------------------
def test_set_pin_actually_sets_the_pin(virtual):
    """The PIN must survive real ECDH + AES-CBC round-tripping."""
    set_pin("123456")
    assert virtual.pin == "123456"


def test_set_pin_unicode_survives_encryption(virtual):
    set_pin("héllo")
    assert virtual.pin == "héllo"


def test_set_pin_rejected_when_already_set(virtual):
    virtual.pin = "1234"
    with pytest.raises(PinError, match="already set"):
        set_pin("999999")
    assert virtual.pin == "1234"


def test_authenticator_enforces_min_pin_length(virtual):
    """Bypass our client check to prove the CTAP error path is translated."""
    virtual.min_pin_length = 8
    with pytest.raises(PinError):
        set_pin("1234")
    assert virtual.pin is None


# ---------------------------------------------------------------------------
# CHANGE PIN through the real PIN protocol
# ---------------------------------------------------------------------------
def test_change_pin_actually_changes_the_pin(virtual):
    virtual.pin = "123456"
    change_pin("123456", "654321")
    assert virtual.pin == "654321"


def test_wrong_old_pin_is_rejected_and_burns_a_retry(virtual):
    """The virtual token verifies the real encrypted PIN hash."""
    virtual.pin = "123456"
    virtual.pin_retries = 5
    with pytest.raises(PinError, match="Incorrect PIN"):
        change_pin("000000", "654321")
    assert virtual.pin == "123456"
    assert virtual.pin_retries == 4


def test_correct_pin_restores_the_retry_counter(virtual):
    virtual.pin = "123456"
    virtual.pin_retries = 3
    change_pin("123456", "654321")
    assert virtual.pin_retries == 8


def test_exhausted_retries_report_blocked(virtual):
    virtual.pin = "123456"
    virtual.pin_retries = 1
    with pytest.raises(PinBlockedError, match="factory reset"):
        change_pin("000000", "654321")


def test_change_pin_on_pinless_token(virtual):
    with pytest.raises(PinError, match="set-pin"):
        change_pin("123456", "654321")


# ---------------------------------------------------------------------------
# FACTORY RESET over real CBOR
# ---------------------------------------------------------------------------
def test_factory_reset_clears_pin_on_the_authenticator(virtual):
    virtual.pin = "123456"
    factory_reset()
    assert virtual.reset_calls == 1
    assert virtual.pin is None


def test_factory_reset_emits_touch_keepalive(virtual):
    seen: list[int] = []
    factory_reset(on_keepalive=seen.append)
    assert 2 in seen, "expected the user-presence keep-alive status"


def test_factory_reset_outside_window_is_translated(virtual):
    virtual.pin = "123456"
    virtual.reset_allowed = False
    with pytest.raises(ResetNotAllowedError, match="few seconds"):
        factory_reset()
    assert virtual.pin == "123456", "a refused reset must not clear the PIN"


# ---------------------------------------------------------------------------
# FULL LIFECYCLE
# ---------------------------------------------------------------------------
def test_provisioning_lifecycle(virtual):
    """set -> change -> reset -> set again, asserting real device state."""
    assert get_device_info().pin_set is False

    set_pin("111111")
    assert virtual.pin == "111111"
    assert get_device_info().pin_set is True

    change_pin("111111", "222222")
    assert virtual.pin == "222222"

    factory_reset()
    assert virtual.pin is None
    assert get_device_info().pin_set is False

    set_pin("333333")
    assert virtual.pin == "333333"


def test_device_handle_is_released(virtual):
    get_device_info()
    assert virtual.closed, "the transport must be closed after each operation"
