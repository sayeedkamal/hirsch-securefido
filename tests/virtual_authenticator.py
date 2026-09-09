"""
A virtual CTAP2 authenticator that speaks the real CBOR wire protocol.

Unlike the fakes in conftest.py, this does NOT stub out fido2. It implements
`CtapDevice.call()` at the byte level, so the genuine `Ctap2`, `ClientPin`,
ECDH key agreement, PIN encryption, and pinUvAuthParam verification all run
for real. That makes it an integration boundary rather than a mock: if our
code sends a malformed request, or python-fido2 changes its protocol, these
tests fail.

It is a stand-in for USB HID transport only. Real hardware I/O, the reset
power-up window, and the physical touch cannot be reproduced in software.
"""

from __future__ import annotations

from hashlib import sha256

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fido2 import cbor
from fido2.ctap import CtapDevice, CtapError
from fido2.ctap2.base import Ctap2
from fido2.ctap2.pin import ClientPin
from fido2.hid import CAPABILITY, CTAPHID


def _unpad_pin(padded: bytes) -> str:
    return padded.rstrip(b"\0").decode()


class VirtualAuthenticator(CtapDevice):
    """
    Implements the subset of CTAP2 this tool exercises: getInfo, clientPin
    (getKeyAgreement / setPIN / changePIN / getPINRetries), and reset.

    PIN protocol two is implemented against the real client, including HKDF
    key derivation, AES-256-CBC decryption, and HMAC-SHA256 verification of
    pinUvAuthParam, so a protocol mistake on our side surfaces as a genuine
    CTAP error rather than a silently accepted mock call.
    """

    capabilities = CAPABILITY.CBOR

    def __init__(
        self,
        pin: str | None = None,
        pin_retries: int = 8,
        min_pin_length: int = 4,
        aaguid: bytes = bytes(range(16)),
        supports_client_pin: bool = True,
    ):
        self.pin = pin
        self.pin_retries = pin_retries
        self.min_pin_length = min_pin_length
        self.aaguid = aaguid
        self.supports_client_pin = supports_client_pin

        self.reset_calls = 0
        self.closed = False
        self.reset_allowed = True
        self.require_touch = True
        self._private_key = ec.generate_private_key(ec.SECP256R1())

    # -- transport ------------------------------------------------------
    def call(self, cmd, data=b"", event=None, on_keepalive=None) -> bytes:
        if cmd != CTAPHID.CBOR:
            raise CtapError(CtapError.ERR.INVALID_COMMAND)
        command = data[0]
        payload = cbor.decode(data[1:]) if len(data) > 1 else {}
        try:
            if command == Ctap2.CMD.GET_INFO:
                response = self._get_info()
            elif command == Ctap2.CMD.CLIENT_PIN:
                response = self._client_pin(payload)
            elif command == Ctap2.CMD.RESET:
                response = self._reset(event, on_keepalive)
            else:
                raise CtapError(CtapError.ERR.INVALID_COMMAND)
        except CtapError as exc:
            return bytes([exc.code])
        return b"\0" + (cbor.encode(response) if response else b"")

    def close(self) -> None:
        self.closed = True

    @classmethod
    def list_devices(cls):
        yield cls()

    # -- commands -------------------------------------------------------
    def _get_info(self) -> dict:
        options = {"rk": True, "up": True}
        if self.supports_client_pin:
            options["clientPin"] = self.pin is not None
        return {
            0x01: ["U2F_V2", "FIDO_2_0", "FIDO_2_1"],
            0x02: ["credProtect", "hmac-secret"],
            0x03: self.aaguid,
            0x04: options,
            0x05: 1200,
            0x06: [2, 1],
            0x07: 8,
            0x08: 128,
            0x0D: self.min_pin_length,
            0x0E: 328966,
        }

    def _client_pin(self, payload: dict):
        subcommand = payload.get(0x02)
        if subcommand == ClientPin.CMD.GET_PIN_RETRIES:
            return {ClientPin.RESULT.PIN_RETRIES: self.pin_retries}
        if subcommand == ClientPin.CMD.GET_KEY_AGREEMENT:
            return {ClientPin.RESULT.KEY_AGREEMENT: self._public_cose()}
        if subcommand == ClientPin.CMD.SET_PIN:
            return self._set_pin(payload)
        if subcommand == ClientPin.CMD.CHANGE_PIN:
            return self._change_pin(payload)
        raise CtapError(CtapError.ERR.INVALID_COMMAND)

    def _set_pin(self, payload: dict):
        if self.pin is not None:
            raise CtapError(CtapError.ERR.PIN_AUTH_INVALID)
        shared = self._shared_secret(payload[0x03])
        self._verify_auth(shared, payload[0x05], payload[0x04])
        new_pin = _unpad_pin(self._decrypt(shared, payload[0x05]))
        if len(new_pin.encode()) < self.min_pin_length:
            raise CtapError(CtapError.ERR.PIN_POLICY_VIOLATION)
        self.pin = new_pin
        return {}

    def _change_pin(self, payload: dict):
        if self.pin is None:
            raise CtapError(CtapError.ERR.PIN_NOT_SET)
        if self.pin_retries <= 0:
            raise CtapError(CtapError.ERR.PIN_BLOCKED)

        shared = self._shared_secret(payload[0x03])
        new_pin_enc, pin_hash_enc = payload[0x05], payload[0x06]
        self._verify_auth(shared, new_pin_enc + pin_hash_enc, payload[0x04])

        supplied = self._decrypt(shared, pin_hash_enc)
        if supplied != sha256(self.pin.encode()).digest()[:16]:
            self.pin_retries -= 1
            if self.pin_retries <= 0:
                raise CtapError(CtapError.ERR.PIN_BLOCKED)
            raise CtapError(CtapError.ERR.PIN_INVALID)

        new_pin = _unpad_pin(self._decrypt(shared, new_pin_enc))
        if len(new_pin.encode()) < self.min_pin_length:
            raise CtapError(CtapError.ERR.PIN_POLICY_VIOLATION)
        self.pin = new_pin
        self.pin_retries = 8
        return {}

    def _reset(self, event, on_keepalive):
        self.reset_calls += 1
        if not self.reset_allowed:
            raise CtapError(CtapError.ERR.NOT_ALLOWED)
        if self.require_touch and on_keepalive:
            on_keepalive(2)  # STATUS.UPNEEDED
        if event is not None and event.is_set():
            raise CtapError(CtapError.ERR.KEEPALIVE_CANCEL)
        self.pin = None
        self.pin_retries = 8
        return {}

    # -- PIN protocol 2 crypto -----------------------------------------
    def _public_cose(self) -> dict:
        numbers = self._private_key.public_key().public_numbers()
        return {
            1: 2,
            3: -25,
            -1: 1,
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        }

    def _shared_secret(self, peer_cose: dict) -> bytes:
        peer = ec.EllipticCurvePublicNumbers(
            int.from_bytes(peer_cose[-2], "big"),
            int.from_bytes(peer_cose[-3], "big"),
            ec.SECP256R1(),
        ).public_key()
        z = self._private_key.exchange(ec.ECDH(), peer)
        # PIN protocol 2 derives a 64-byte key: HMAC key then AES key.
        hmac_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=b"\0" * 32,
            info=b"CTAP2 HMAC key",
        ).derive(z)
        aes_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=b"\0" * 32,
            info=b"CTAP2 AES key",
        ).derive(z)
        return hmac_key + aes_key

    def _decrypt(self, shared: bytes, data: bytes) -> bytes:
        iv, ciphertext = data[:16], data[16:]
        decryptor = Cipher(
            algorithms.AES(shared[32:]), modes.CBC(iv)
        ).decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def _verify_auth(self, shared: bytes, message: bytes, signature: bytes) -> None:
        import hmac

        expected = hmac.new(shared[:32], message, sha256).digest()
        if not hmac.compare_digest(expected, signature):
            raise CtapError(CtapError.ERR.PIN_AUTH_INVALID)
