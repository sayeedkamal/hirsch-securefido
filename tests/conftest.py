"""
Shared fakes so the whole suite runs with no authenticator attached.

The fakes model the CTAP surface the tool actually touches: an Info object,
ClientPin's set_pin/change_pin/get_pin_retries, and Ctap2.reset.
"""

from __future__ import annotations

import pytest
from fido2.ctap import CtapError

from hirsch_securefido import device as dev_mod


class FakeInfo:
    def __init__(self, **overrides):
        self.versions = ["U2F_V2", "FIDO_2_0", "FIDO_2_1"]
        self.extensions = ["credProtect", "hmac-secret"]
        self.aaguid = bytes(range(16))
        self.options = {"rk": True, "up": True, "clientPin": True, "credMgmt": True}
        self.max_msg_size = 1200
        self.pin_uv_protocols = [2, 1]
        self.max_creds_in_list = 8
        self.max_cred_id_length = 128
        self.algorithms = [{"alg": -7, "type": "public-key"}, {"alg": -257}]
        self.max_large_blob = None
        self.force_pin_change = False
        self.min_pin_length = 4
        self.max_pin_length = 63
        self.firmware_version = 328966
        self.remaining_disc_creds = 24
        for key, value in overrides.items():
            setattr(self, key, value)


class FakeDescriptor:
    def __init__(self, vid=0x04E6, product_name="Hirsch SecureKey"):
        self.vid = vid
        self.product_name = product_name


class FakeHidDevice:
    def __init__(self, vid=0x04E6, product_name="Hirsch SecureKey"):
        self.descriptor = FakeDescriptor(vid, product_name)
        self.closed = False

    def close(self):
        self.closed = True


class FakeClientPin:
    """Records calls and replays a scripted error, if one was set."""

    last: FakeClientPin | None = None

    def __init__(self, ctap, protocol=None):
        self.ctap = ctap
        self.set_pin_calls: list[str] = []
        self.change_pin_calls: list[tuple[str, str]] = []
        FakeClientPin.last = self

    def get_pin_retries(self):
        return (self.ctap.pin_retries, None)

    def set_pin(self, pin):
        if self.ctap.raise_on_set is not None:
            raise self.ctap.raise_on_set
        self.set_pin_calls.append(pin)
        self.ctap.info.options["clientPin"] = True

    def change_pin(self, old_pin, new_pin):
        if self.ctap.raise_on_change is not None:
            raise self.ctap.raise_on_change
        self.change_pin_calls.append((old_pin, new_pin))


class FakeCtap2:
    def __init__(self, device, info=None):
        self.device = device
        self.info = info if info is not None else FakeInfo()
        self.pin_retries = 8
        self.raise_on_set: Exception | None = None
        self.raise_on_change: Exception | None = None
        self.raise_on_reset: Exception | None = None
        self.reset_calls = 0

    def reset(self, *, event=None, on_keepalive=None):
        self.reset_calls += 1
        if on_keepalive:
            on_keepalive(2)
        if self.raise_on_reset is not None:
            raise self.raise_on_reset
        self.info.options["clientPin"] = False


@pytest.fixture
def fake_token(monkeypatch):
    """
    Install a single fake Hirsch HID token. Yields the FakeCtap2 so a test can
    script errors (`token.raise_on_set = CtapError(0x31)`) or assert calls.
    """
    hid = FakeHidDevice()
    ctap = FakeCtap2(hid)
    # Clear the cross-test record, otherwise a test that asserts "no PIN call
    # was made" can pass/fail on the previous test's FakeClientPin.
    FakeClientPin.last = None

    monkeypatch.setattr(
        dev_mod.CtapHidDevice, "list_devices", staticmethod(lambda: [hid])
    )
    monkeypatch.setattr(dev_mod, "Ctap2", lambda device: ctap)
    monkeypatch.setattr(dev_mod, "ClientPin", FakeClientPin)
    monkeypatch.setattr(dev_mod, "HAVE_PCSC", False)
    ctap.hid = hid
    return ctap


@pytest.fixture
def no_token(monkeypatch):
    monkeypatch.setattr(
        dev_mod.CtapHidDevice, "list_devices", staticmethod(lambda: [])
    )
    monkeypatch.setattr(dev_mod, "HAVE_PCSC", False)


def ctap_error(name: str) -> CtapError:
    return CtapError(CtapError.ERR[name])
