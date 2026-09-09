"""Tests for the device-configuration layer."""

from __future__ import annotations

import pytest
from conftest import FakeClientPin, FakeHidDevice, ctap_error

from hirsch_securefido import device as dev_mod
from hirsch_securefido.device import (
    DeviceNotFoundError,
    PinBlockedError,
    PinError,
    ResetNotAllowedError,
    UnsupportedOperationError,
    change_pin,
    factory_reset,
    get_device_info,
    list_devices,
    set_pin,
)


# ---------------------------------------------------------------------------
# DISCOVERY
# ---------------------------------------------------------------------------
def test_list_devices_finds_hirsch_token(fake_token):
    devices = list_devices()
    assert len(devices) == 1
    transport, product = devices[0]
    assert "04E6" in transport
    assert product == "Hirsch SecureKey"


def test_no_device_raises(no_token):
    with pytest.raises(DeviceNotFoundError):
        get_device_info()


def test_foreign_vendor_filtered_by_default(monkeypatch):
    foreign = FakeHidDevice(vid=0x1050, product_name="Other Key")
    monkeypatch.setattr(
        dev_mod.CtapHidDevice, "list_devices", staticmethod(lambda: [foreign])
    )
    monkeypatch.setattr(dev_mod, "HAVE_PCSC", False)
    assert list_devices() == []
    assert list_devices(any_vendor=True) != []
    # A filtered-out device must not be left open holding the HID handle.
    assert foreign.closed


# ---------------------------------------------------------------------------
# DEVICE INFO
# ---------------------------------------------------------------------------
def test_get_device_info_fields(fake_token):
    info = get_device_info()
    assert info.aaguid == "00010203-0405-0607-0809-0a0b0c0d0e0f"
    assert info.pin_set is True
    assert info.pin_retries == 8
    assert "FIDO_2_1" in info.versions
    assert "ES256" in info.algorithms and "RS256" in info.algorithms
    assert info.min_pin_length == 4
    assert info.firmware_version == 328966


def test_info_option_rows_are_labelled(fake_token):
    rows = dict(get_device_info().option_rows)
    assert rows["Resident Keys"] is True
    assert rows["Client PIN"] is True


def test_info_as_dict_is_json_safe(fake_token):
    import json

    payload = json.dumps(get_device_info().as_dict())
    assert "aaguid" in payload


def test_info_without_pin_set(fake_token):
    fake_token.info.options["clientPin"] = False
    info = get_device_info()
    assert info.pin_set is False


def test_device_handle_closed_after_info(fake_token):
    get_device_info()
    assert fake_token.hid.closed


# ---------------------------------------------------------------------------
# SET PIN
# ---------------------------------------------------------------------------
def test_set_pin_on_fresh_token(fake_token):
    fake_token.info.options["clientPin"] = False
    set_pin("123456")
    assert FakeClientPin.last.set_pin_calls == ["123456"]


def test_set_pin_refuses_when_pin_exists(fake_token):
    fake_token.info.options["clientPin"] = True
    with pytest.raises(PinError, match="already set"):
        set_pin("123456")


def test_set_pin_requires_client_pin_support(fake_token):
    fake_token.info.options.pop("clientPin")
    with pytest.raises(UnsupportedOperationError):
        set_pin("123456")


def test_set_pin_enforces_minimum_length(fake_token):
    fake_token.info.options["clientPin"] = False
    fake_token.info.min_pin_length = 6
    with pytest.raises(PinError, match="too short"):
        set_pin("1234")


def test_set_pin_enforces_maximum_length(fake_token):
    fake_token.info.options["clientPin"] = False
    fake_token.info.max_pin_length = 8
    with pytest.raises(PinError, match="too long"):
        set_pin("1" * 20)


def test_pin_length_measured_in_utf8_bytes(fake_token):
    """CTAP counts UTF-8 bytes, so 4 multi-byte glyphs satisfy a min of 4."""
    fake_token.info.options["clientPin"] = False
    fake_token.info.min_pin_length = 4
    set_pin("héllo")
    assert FakeClientPin.last.set_pin_calls == ["héllo"]


def test_set_pin_policy_violation_is_translated(fake_token):
    fake_token.info.options["clientPin"] = False
    fake_token.raise_on_set = ctap_error("PIN_POLICY_VIOLATION")
    with pytest.raises(PinError, match="policy"):
        set_pin("123456")


# ---------------------------------------------------------------------------
# CHANGE PIN
# ---------------------------------------------------------------------------
def test_change_pin_succeeds(fake_token):
    change_pin("123456", "654321")
    assert FakeClientPin.last.change_pin_calls == [("123456", "654321")]


def test_change_pin_requires_existing_pin(fake_token):
    fake_token.info.options["clientPin"] = False
    with pytest.raises(PinError, match="set-pin"):
        change_pin("123456", "654321")


def test_change_pin_rejects_identical_pin(fake_token):
    with pytest.raises(PinError, match="must differ"):
        change_pin("123456", "123456")


def test_wrong_pin_reports_remaining_retries(fake_token):
    fake_token.raise_on_change = ctap_error("PIN_INVALID")
    fake_token.pin_retries = 3
    with pytest.raises(PinError, match="3 attempt") as excinfo:
        change_pin("000000", "654321")
    assert excinfo.value.retries == 3


def test_pin_blocked_is_translated(fake_token):
    fake_token.raise_on_change = ctap_error("PIN_BLOCKED")
    with pytest.raises(PinBlockedError, match="factory reset"):
        change_pin("123456", "654321")


def test_pin_auth_blocked_suggests_reseat(fake_token):
    fake_token.raise_on_change = ctap_error("PIN_AUTH_BLOCKED")
    with pytest.raises(PinBlockedError, match="re-insert"):
        change_pin("123456", "654321")


# ---------------------------------------------------------------------------
# FACTORY RESET
# ---------------------------------------------------------------------------
def test_factory_reset_invokes_reset(fake_token):
    factory_reset()
    assert fake_token.reset_calls == 1
    assert fake_token.info.options["clientPin"] is False


def test_factory_reset_reports_touch_prompt(fake_token):
    seen: list[int] = []
    factory_reset(on_keepalive=seen.append)
    assert 2 in seen


def test_factory_reset_window_expired(fake_token):
    fake_token.raise_on_reset = ctap_error("NOT_ALLOWED")
    with pytest.raises(ResetNotAllowedError, match="few seconds"):
        factory_reset()


def test_factory_reset_touch_timeout(fake_token):
    fake_token.raise_on_reset = ctap_error("ACTION_TIMEOUT")
    with pytest.raises(ResetNotAllowedError, match="touch"):
        factory_reset()


def test_factory_reset_declined(fake_token):
    fake_token.raise_on_reset = ctap_error("OPERATION_DENIED")
    with pytest.raises(ResetNotAllowedError, match="declined"):
        factory_reset()


def test_factory_reset_without_device(no_token):
    with pytest.raises(DeviceNotFoundError):
        factory_reset()


# ---------------------------------------------------------------------------
# SCOPE GUARD - credential management must NOT be present
# ---------------------------------------------------------------------------
def test_no_credential_management_surface():
    """
    This package is the device-configuration subset only. Enumerating or
    deleting credentials must not be reachable from it.
    """
    import hirsch_securefido

    exported = set(dir(hirsch_securefido)) | set(dir(dev_mod))
    for banned in (
        "CredManSession",
        "enumerate_all",
        "delete_credential",
        "CredentialManagement",
    ):
        assert banned not in exported, f"{banned} leaked into the config package"
