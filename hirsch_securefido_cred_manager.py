# ---------------------------------------------------------------------------
# Copyright (c) 2026, Hirsch Secure, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
# ---------------------------------------------------------------------------
"""
Hirsch SecureFIDO Cred Manager
==============================
Windows desktop application for managing FIDO2 discoverable credentials
(passkeys) on Hirsch SecureKey / SecureKey GOV devices.

This is the FIDO2 sibling of the Hirsch SecurePIV Assistant and shares its
single-window product design: navy header, collapsible sidebar, main
operation card, and a live SYSTEM EVENT LOG.

Behaviour
---------
  * Auto-elevates to Administrator on launch. On Windows, non-elevated
    processes are blocked from opening FIDO HID authenticators, so this is
    required for the USB-HID path (not merely product parity).
  * Startup hardware gate: refuses to launch unless a reader/key with the
    Hirsch-approved USB Vendor ID (VID_04E6) is present. VID-only check via
    SCardGetReaderDeviceInstanceIdW - no SCardConnect, no reader lock.
  * Live disconnect watchdog via cfgmgr32 CM_Locate_DevNodeW; closes the app
    if the confirmed device is physically removed.

Credential management (CTAP 2.1 authenticatorCredentialManagement, python-fido2):
  * getCredsMetadata      (storage used / remaining)
  * enumerateRPs / enumerateCredentials
  * deleteCredential
A fresh pinUvAuthToken (CREDENTIAL_MGMT permission) is acquired per operation,
so token expiry between UI actions never surfaces to the user.

Dependencies (Windows, Python 3.10+):
    pip install customtkinter fido2==1.2.0 pyscard pillow

NOTE on pyscard >= 2.2: fido2 1.2.0 imports smartcard.pcsc.PCSCContext,
removed from newer pyscard releases. Either pin pyscard==2.0.7 or drop the
one-file compatibility shim into site-packages/smartcard/pcsc/ (see README).
"""

from __future__ import annotations

import base64
import ctypes
import os
import re
import sys
import threading
import time
from datetime import datetime

import customtkinter as ctk
from tkinter import messagebox

try:
    from PIL import Image, ImageTk
    HAVE_PIL = True
except Exception:
    HAVE_PIL = False

# ---------------------------------------------------------------------------
# APP IDENTITY
# ---------------------------------------------------------------------------
APP_NAME = "Hirsch SecureFIDO Cred Manager"
APP_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# WINDOWS NATIVE API HANDLES (loaded once at module level)
# ---------------------------------------------------------------------------
HIRSCH_VID = "04E6"                 # SCM/Identiv/Hirsch USB Vendor ID
SCARD_SCOPE_SYSTEM = 2
SCARD_S_SUCCESS = 0
CR_SUCCESS = 0
CM_LOCATE_DEVNODE_NORMAL = 0

# Optional allow-list for USB HID FIDO2 keys (Hirsch SecureKey USB models).
ALLOWED_HID_VIDS = (0x04E6,)

if sys.platform.startswith("win"):
    _winscard = ctypes.WinDLL("winscard.dll")
    _cfgmgr32 = ctypes.WinDLL("cfgmgr32.dll")
else:
    _winscard = None
    _cfgmgr32 = None

# ---------------------------------------------------------------------------
# BRAND TOKENS (from Hirsch SecurePIV Assistant design)
# ---------------------------------------------------------------------------
BRAND_MIDNIGHT = "#002b45"
BRAND_GREEN = "#92D400"
BG_MAIN = "#DAE3EA"
BG_CARD = "#FFFFFF"
TEXT_DARK = "#2C3E50"
TEXT_SUB = "#7F8C8D"
INPUT_BG = "#F0F3F5"
BORDER_GRAY = "#CBD6E2"
LOG_HEADER_BG = "#F4F7F9"
DANGER = "#B03A2E"

# Avatar palette for credential relying-party initials
AVATAR_PALETTE = [
    ("#CFE3F7", "#1E4F82"),
    ("#A5E9E4", "#067F87"),
    ("#E4D9F2", "#5B3E8C"),
    ("#DDEDC8", "#4C7A1F"),
]

PROTECT_NAMES = {
    1: "userVerificationOptional",
    2: "userVerificationOptionalWithCredentialIDList",
    3: "userVerificationRequired",
}
ALG_NAMES = {-7: "ES256", -8: "EdDSA", -35: "ES384", -36: "ES512",
             -257: "RS256", -47: "ES256K"}
OPTION_LABELS = [
    ("rk", "Resident Keys"),
    ("up", "User Presence"),
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
# HELPERS
# ---------------------------------------------------------------------------

def discover_hirsch_reader():
    """
    Startup-only discovery. Establishes a temporary SCard context, enumerates
    present readers, calls SCardGetReaderDeviceInstanceIdW on each, and
    regex-validates VID against the HIRSCH_VID allow-list. No SCardConnect is
    issued, so the check acquires no reader lock and works with a card seated.

    Returns (reader_name, instance_id) for the first confirmed Hirsch reader,
    or (None, None) if none is found or on any failure.
    """
    if not sys.platform.startswith("win"):
        return ("bypass", "bypass")

    try:
        hContext = ctypes.c_void_p(None)
        if _winscard.SCardEstablishContext(
                SCARD_SCOPE_SYSTEM, None, None,
                ctypes.byref(hContext)) != SCARD_S_SUCCESS:
            return (None, None)
        try:
            cch = ctypes.c_ulong(0)
            _winscard.SCardListReadersW(hContext, None, None, ctypes.byref(cch))
            if cch.value == 0:
                return (None, None)

            buf = ctypes.create_unicode_buffer(cch.value)
            if _winscard.SCardListReadersW(
                    hContext, None, buf, ctypes.byref(cch)) != SCARD_S_SUCCESS:
                return (None, None)

            reader_names = [s for s in buf[:cch.value].split("\x00") if s]

            for reader_name in reader_names:
                id_buf_size = ctypes.c_ulong(256)
                id_buf = ctypes.create_unicode_buffer(256)
                if _winscard.SCardGetReaderDeviceInstanceIdW(
                        hContext, ctypes.c_wchar_p(reader_name),
                        id_buf, ctypes.byref(id_buf_size)) != SCARD_S_SUCCESS:
                    continue
                instance_id = id_buf.value
                vid_match = re.search(r"VID_([0-9A-Fa-f]{4})", instance_id)
                if vid_match and vid_match.group(1).upper() == HIRSCH_VID:
                    return (reader_name, instance_id)
        finally:
            _winscard.SCardReleaseContext(hContext)
    except Exception:
        pass
    return (None, None)


def is_reader_present(instance_id=None):
    """
    Runtime presence check via cfgmgr32 CM_Locate_DevNodeW. No PowerShell, no
    subprocess, no PC/SC stack. Completes in microseconds.

    CM_LOCATE_DEVNODE_NORMAL only matches active, present devnodes. Physical
    disconnect removes the devnode -> CR_NO_SUCH_DEVINST -> returns False ->
    watchdog fires _on_device_removed().
    """
    if not sys.platform.startswith("win"):
        return True
    if not instance_id or instance_id == "bypass":
        return True     # startup gate already confirmed hardware
    try:
        devnode = ctypes.c_ulong(0)
        ret = _cfgmgr32.CM_Locate_DevNodeW(
            ctypes.byref(devnode),
            ctypes.c_wchar_p(instance_id),
            ctypes.c_ulong(CM_LOCATE_DEVNODE_NORMAL))
        return ret == CR_SUCCESS
    except Exception:
        return False


def resource_path(relative_name):
    """Absolute path to a bundled resource (PyInstaller _MEIPASS or source dir)."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, relative_name)


def is_admin():
    if sys.platform.startswith("win"):
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return os.getuid() == 0 if hasattr(os, "getuid") else False


# Logo caches: the source PNG is ~3763x3617, so decode+downscale it ONCE and
# reuse the result. Re-opening it per call was slow and occasionally crashed
# ImageTk under memory pressure (PyImagingPhoto / WinError 299).
_LOGO_BASE = None                       # base PIL image, loaded + pre-shrunk once
_LOGO_CTK_CACHE: dict = {}              # size -> CTkImage
_LOGO_TK_CACHE: dict = {}               # size -> ImageTk.PhotoImage (kept alive)


def _logo_base():
    """Load and pre-shrink the logo PIL image once; cache module-wide."""
    global _LOGO_BASE
    if _LOGO_BASE is not None or not HAVE_PIL:
        return _LOGO_BASE
    try:
        path = resource_path("hirsch_logo.png")
        if os.path.exists(path):
            img = Image.open(path).convert("RGBA")
            img.thumbnail((256, 256), Image.LANCZOS)   # cheap per-size resizes after
            _LOGO_BASE = img
            return _LOGO_BASE
    except Exception:
        pass
    _LOGO_BASE = Image.new("RGBA", (256, 256), BRAND_MIDNIGHT)   # fallback
    return _LOGO_BASE


def create_logo_ctkimage(size=(40, 40)):
    """Cached CTkImage of the Hirsch logo at the requested size."""
    cached = _LOGO_CTK_CACHE.get(size)
    if cached is not None:
        return cached
    base = _logo_base()
    if base is None:
        return None
    img = ctk.CTkImage(light_image=base, dark_image=base, size=size)
    _LOGO_CTK_CACHE[size] = img
    return img


def logo_tk_photo(size=(32, 32)):
    """Cached ImageTk.PhotoImage of the logo (for wm_iconphoto)."""
    cached = _LOGO_TK_CACHE.get(size)
    if cached is not None:
        return cached
    base = _logo_base()
    if base is None:
        return None
    photo = ImageTk.PhotoImage(base.resize(size, Image.LANCZOS))
    _LOGO_TK_CACHE[size] = photo
    return photo


def avatar_colors(rp_id: str) -> tuple[str, str]:
    return AVATAR_PALETTE[sum(ord(c) for c in rp_id) % len(AVATAR_PALETTE)]


# ---------------------------------------------------------------------------
# FIDO2 device + credential management layer (python-fido2)
# ---------------------------------------------------------------------------

from fido2.ctap import CtapError                                   # noqa: E402
from fido2.ctap2 import Ctap2, ClientPin, CredentialManagement     # noqa: E402
from fido2.hid import CtapHidDevice                                # noqa: E402
from fido2.webauthn import (                                       # noqa: E402
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialType,
)

try:
    from fido2.pcsc import CtapPcscDevice
    HAVE_PCSC = True
except Exception:
    CtapPcscDevice = None
    HAVE_PCSC = False


def get_fido_candidates() -> list[tuple[object, str]]:
    """
    Collect ALL candidate CTAP devices, HID FIRST, then PC/SC.

    HID-first is deliberate: composite keys (uTrust FIDO2, VID 04E6 /
    PID 5A11) expose a CCID/PC/SC face and a CTAP HID face over ONE secure
    element. Merely opening and closing the CCID face schedules a deferred
    card unpower by the Windows resource manager, which resets the shared SE
    mid-HID-session and invalidates the pinUvAuthToken (observed as CTAP 0x33
    PIN_AUTH_INVALID on the first credman call). Probing HID first means the
    CCID face is never touched when a HID key is present; PC/SC remains the
    path for NFC cards seated on a reader.
    """
    cands: list[tuple[object, str]] = []

    for dev in CtapHidDevice.list_devices():
        vid = getattr(dev.descriptor, "vid", None)
        if vid in ALLOWED_HID_VIDS:
            cands.append((dev, f"USB HID (VID {vid:04X})"))

    if HAVE_PCSC and not cands:
        try:
            for dev in CtapPcscDevice.list_devices():
                name = getattr(dev, "_name", None) or "reader"
                cands.append((dev, f"PC/SC ({name})"))
        except Exception:
            pass

    return cands


def probe_device():
    """Open the first CTAP2-capable candidate. Returns (label, ctap2, dev)."""
    skipped = []
    for dev, label in get_fido_candidates():
        try:
            return label, Ctap2(dev), dev
        except Exception as e:
            skipped.append(f"{label}: {e}")
            try:
                dev.close()
            except Exception:
                pass
    detail = ("\n" + "\n".join(skipped)) if skipped else ""
    raise RuntimeError("No CTAP2-capable Hirsch token found." + detail)


def get_device_status():
    """Returns (transport_label, info, pin_retries_or_None). No PIN needed."""
    label, ctap2, dev = probe_device()
    try:
        info = ctap2.info
        retries = None
        if (info.options or {}).get("clientPin"):
            try:
                retries = ClientPin(ctap2).get_pin_retries()[0]
            except Exception:
                pass
        return label, info, retries
    finally:
        try:
            dev.close()
        except Exception:
            pass


class CredManSession:
    """
    Wraps one authenticated credentialManagement exchange. A fresh
    pinUvAuthToken (CREDENTIAL_MGMT permission) is acquired per session so
    token expiry between UI actions never surfaces to the user.
    """

    def __init__(self, pin: str):
        candidates = get_fido_candidates()
        if not candidates:
            raise RuntimeError(
                "No Hirsch FIDO2 token found. Seat the card on the reader "
                "or insert an approved USB key.")

        self.device = None
        self.ctap2 = None
        self.transport = ""
        skipped: list[str] = []

        for dev, label in candidates:
            try:
                ctap2 = Ctap2(dev)
            except Exception as e:
                skipped.append(f"{label}: {e}")
                try:
                    dev.close()
                except Exception:
                    pass
                continue

            # Ask python-fido2 rather than testing info.options here.
            # Its is_supported() ALSO requires FIDO_2_1_PRE in versions
            # before it will use the prototype command, so testing the
            # option alone let through tokens that CredentialManagement
            # then refused with a bare ValueError - raised in
            # _acquire_token(), i.e. AFTER the operator's correct PIN
            # had been accepted and a pinUvAuthToken spent. On screen
            # that reads as "credential management is broken" rather
            # than "this token cannot do it". Refuse up front instead,
            # using exactly the test the library applies later.
            if not CredentialManagement.is_supported(ctap2.info):
                skipped.append(
                    f"{label}: no CTAP 2.1 credential management "
                    "(credMgmt); this token cannot list or delete "
                    "resident credentials")
                try:
                    dev.close()
                except Exception:
                    pass
                continue

            self.device, self.ctap2, self.transport = dev, ctap2, label
            break

        if self.ctap2 is None:
            detail = "\n".join(skipped) if skipped else "no usable device"
            raise RuntimeError(
                "Credential management (CTAP 2.1 credMgmt) is not "
                f"available on any connected token:\n{detail}")

        opts = (self.ctap2.info.options or {})
        if not opts.get("clientPin"):
            raise RuntimeError("No PIN is set on this token. Set a PIN first.")

        self._session_pin = pin
        self._acquire_token()

    def _acquire_token(self) -> None:
        client_pin = ClientPin(self.ctap2)
        try:
            token = client_pin.get_pin_token(
                self._session_pin,
                permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
        except CtapError as e:
            if e.code == CtapError.ERR.PIN_INVALID:
                raise RuntimeError("Incorrect PIN.") from e
            if e.code == CtapError.ERR.PIN_AUTH_BLOCKED:
                raise RuntimeError(
                    "PIN auth blocked - remove and re-seat the token.") from e
            if e.code == CtapError.ERR.PIN_BLOCKED:
                raise RuntimeError(
                    "PIN permanently blocked - factory reset required.") from e
            raise
        self.cm = CredentialManagement(self.ctap2, client_pin.protocol, token)

    def _authed(self, fn, *args):
        """
        Run one credman call; on PIN_AUTH_INVALID (0x33) - token invalidated
        externally, e.g. the composite key's SE reset by a CCID interface
        unpower - re-acquire the token once and retry. Costs no PIN retry.
        """
        try:
            return fn(*args)
        except CtapError as e:
            if e.code != CtapError.ERR.PIN_AUTH_INVALID:
                raise
            self._acquire_token()
            return fn(*args)

    def metadata(self) -> tuple[int, int]:
        data = self._authed(self.cm.get_metadata)
        existing = data.get(CredentialManagement.RESULT.EXISTING_CRED_COUNT, 0)
        remaining = data.get(CredentialManagement.RESULT.MAX_REMAINING_COUNT, 0)
        return existing, remaining

    def enumerate_all(self) -> list[dict]:
        out = []
        try:
            rps = self._authed(self.cm.enumerate_rps)
        except CtapError as e:
            if e.code == CtapError.ERR.NO_CREDENTIALS:
                return out
            raise

        for rp in rps:
            rp_ent = rp.get(CredentialManagement.RESULT.RP, {}) or {}
            rp_hash = rp.get(CredentialManagement.RESULT.RP_ID_HASH)
            entry = {
                "rp_id": rp_ent.get("id", "(unknown rp)"),
                "rp_id_hash": rp_hash,
                "creds": [],
            }
            try:
                creds = self._authed(self.cm.enumerate_creds, rp_hash)
            except CtapError as e:
                if e.code == CtapError.ERR.NO_CREDENTIALS:
                    creds = []
                else:
                    raise
            for c in creds:
                user = c.get(CredentialManagement.RESULT.USER, {}) or {}
                desc = c.get(CredentialManagement.RESULT.CREDENTIAL_ID, {}) or {}
                cred_bytes = desc.get("id", b"")
                pub = c.get(CredentialManagement.RESULT.PUBLIC_KEY, {}) or {}
                alg = None
                try:
                    alg = pub.get(3)        # COSE key: label 3 = algorithm
                except Exception:
                    alg = None
                entry["creds"].append({
                    "user_name": user.get("name", "") or "",
                    "display_name": user.get("displayName", "") or "",
                    "user_id_b64": base64.b64encode(user.get("id", b"")).decode(),
                    "cred_id_b64": base64.b64encode(cred_bytes).decode(),
                    "cred_id_bytes": cred_bytes,
                    "protect": c.get(CredentialManagement.RESULT.CRED_PROTECT, ""),
                    "alg": alg,     # COSE alg int (e.g. -7 ES256); None if unavailable
                })
            out.append(entry)
        return out

    def delete_credential(self, cred_id_bytes: bytes) -> None:
        self._authed(self.cm.delete_cred, PublicKeyCredentialDescriptor(
            type=PublicKeyCredentialType.PUBLIC_KEY, id=cred_id_bytes))

    def close(self) -> None:
        try:
            self.device.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# CUSTOM TOPLEVEL - applies the Hirsch logo, blocks the default CTk icon
# ---------------------------------------------------------------------------
class HirschToplevel(ctk.CTkToplevel):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._apply_hirsch_icon()

    def _apply_hirsch_icon(self):
        try:
            photo = logo_tk_photo((32, 32))
            if photo is not None:
                self.wm_iconphoto(False, photo)
                self._hirsch_icon_ref = photo
        except Exception:
            pass

    def _windows_set_titlebar_icon(self):
        self._apply_hirsch_icon()


# ---------------------------------------------------------------------------
# MAIN GUI APPLICATION
# ---------------------------------------------------------------------------
class SecureFidoApp(ctk.CTk):
    def __init__(self, instance_id=None):
        super().__init__()
        self.instance_id = instance_id
        self._device_removed = False
        self._pin: str | None = None          # cached session PIN
        self._busy = False
        self._font_cache: dict[tuple[int, bool], ctk.CTkFont] = {}
        self._log_lines = 0

        ctk.set_appearance_mode("Light")
        self.configure(fg_color=BG_MAIN)
        self.title(APP_NAME)
        # Center in a single pass: compute position up front (screen dims are
        # known once the root exists) and set geometry once, avoiding the extra
        # layout pass + visible window jump of a post-hoc recenter.
        w, h = 1040, 740
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw - w) // 2}+{max(0, (sh - h) // 2 - 20)}")
        self.minsize(w, h)
        self.resizable(False, False)

        if sys.platform.startswith("win"):
            try:
                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                    "hirsch.securefido.credmanager.1.0")
            except Exception:
                pass
        try:
            png_path = resource_path("hirsch_logo.png")
            ico_path = resource_path("hirsch_logo.ico")
            if HAVE_PIL and os.path.exists(png_path):
                if not os.path.exists(ico_path):
                    Image.open(png_path).save(ico_path, format="ICO",
                                              sizes=[(32, 32)])
                self.iconbitmap(ico_path)
        except Exception:
            pass

        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(1, weight=1)

        self._build_header()
        self._build_sidebar()
        self._build_main_container()

        self.log_event("SYSTEM: Application initialized.")
        self.select_view("device_details")
        # Kick the first device read from the event loop (not __init__) so the
        # worker thread's self.after(...) calls always land in a running loop.
        self.after(200, lambda: self._run_threaded(self._cmd_load_details))
        self._start_disconnect_watchdog()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # -- font helper ------------------------------------------------------
    def font(self, size, bold=False):
        # Cache by (size, bold): there are only ~7 distinct specs in the app,
        # and each CTkFont registers with CTk's scaling manager, so reusing
        # one instance across many widgets avoids hundreds of allocations.
        key = (size, bold)
        f = self._font_cache.get(key)
        if f is None:
            f = ctk.CTkFont(size=size, weight="bold" if bold else "normal")
            self._font_cache[key] = f
        return f

    # -- UI builders ------------------------------------------------------
    def _build_header(self):
        f = ctk.CTkFrame(self, height=75, corner_radius=0,
                         fg_color=BRAND_MIDNIGHT)
        f.grid(row=0, column=0, columnspan=2, sticky="nsew")
        logo = create_logo_ctkimage()
        if logo is not None:
            ctk.CTkLabel(f, image=logo, text="").grid(
                row=0, column=0, padx=(20, 10), pady=15)
        ctk.CTkLabel(f, text="SECURE IDENTITY SOLUTIONS",
                     font=self.font(13, bold=True),
                     text_color="white").grid(row=0, column=1, pady=20)
        ctk.CTkButton(
            f, text="ABOUT", width=80, height=32,
            fg_color="transparent", border_width=1, border_color="white",
            text_color="white", hover_color=BRAND_GREEN,
            font=self.font(11, bold=True),
            command=self._show_about_popup
        ).grid(row=0, column=2, padx=(0, 20), pady=15, sticky="e")
        f.grid_columnconfigure(2, weight=1)

    def _build_sidebar(self):
        self.sidebar_frame = ctk.CTkFrame(self, width=220, corner_radius=0,
                                          fg_color=BG_CARD)
        self.sidebar_frame.grid(row=1, column=0, sticky="nsew")
        self.sidebar_frame.pack_propagate(False)

        menu_groups = [
            ("DIAGNOSTICS", [
                ("device_details", "Device Details"),
            ]),
            ("CREDENTIALS", [
                ("credentials", "Saved Credentials"),
            ]),
        ]

        btn_kwargs = {
            "fg_color": "transparent", "text_color": TEXT_DARK,
            "hover_color": INPUT_BG, "anchor": "w",
            "font": self.font(13, bold=True),
        }

        self.nav_buttons = {}
        self.menu_frames = {}

        ctk.CTkFrame(self.sidebar_frame, height=20,
                     fg_color="transparent").pack(fill="x")

        for group_title, items in menu_groups:
            group_container = ctk.CTkFrame(self.sidebar_frame,
                                           fg_color="transparent")
            group_container.pack(fill="x", padx=10, pady=5)

            is_default_open = (group_title == "DIAGNOSTICS")
            arrow = "▼" if is_default_open else "▶"

            header_btn = ctk.CTkButton(
                group_container, text=f"{arrow}  {group_title}",
                font=self.font(11, bold=True), text_color=TEXT_SUB,
                fg_color="transparent", hover_color=INPUT_BG, anchor="w",
                command=lambda t=group_title: self.toggle_menu(t))
            header_btn.pack(fill="x")

            items_frame = ctk.CTkFrame(group_container, fg_color="transparent")
            if is_default_open:
                items_frame.pack(fill="x", padx=(15, 0), pady=(2, 0))

            self.menu_frames[group_title] = {
                "frame": items_frame, "btn": header_btn,
                "is_open": is_default_open}

            for key, text in items:
                btn = ctk.CTkButton(items_frame, text=text,
                                    command=lambda k=key: self.select_view(k),
                                    **btn_kwargs)
                btn.pack(fill="x", pady=2)
                self.nav_buttons[key] = btn

    def toggle_menu(self, group_title):
        menu_data = self.menu_frames[group_title]
        if menu_data["is_open"]:
            menu_data["frame"].pack_forget()
            menu_data["btn"].configure(text=f"▶  {group_title}")
            menu_data["is_open"] = False
        else:
            menu_data["frame"].pack(fill="x", padx=(15, 0), pady=(2, 0))
            menu_data["btn"].configure(text=f"▼  {group_title}")
            menu_data["is_open"] = True

    def _build_main_container(self):
        self.right_container = ctk.CTkFrame(self, fg_color="transparent")
        self.right_container.grid(row=1, column=1, sticky="nsew")
        self.right_container.grid_columnconfigure(0, weight=1)
        self.right_container.grid_rowconfigure(0, weight=10)
        self.right_container.grid_rowconfigure(1, weight=1)

        self.op_window = ctk.CTkFrame(self.right_container, corner_radius=6,
                                      fg_color=BG_CARD, border_width=1,
                                      border_color=BORDER_GRAY)
        self.op_window.grid(row=0, column=0, sticky="nsew", padx=25,
                            pady=(25, 12))

        self.card_views = {}
        self.entry_kwargs = {"fg_color": INPUT_BG, "border_color": BORDER_GRAY,
                             "border_width": 1, "text_color": TEXT_DARK,
                             "width": 300, "height": 38}
        self.primary_btn_kwargs = {"fg_color": BRAND_GREEN, "text_color": "white",
                                   "hover_color": BRAND_MIDNIGHT,
                                   "font": self.font(13, bold=True), "height": 40}

        self._build_device_details_view()
        self._build_credentials_view()

        # -- SYSTEM EVENT LOG -------------------------------------------
        self.log_frame = ctk.CTkFrame(self.right_container, fg_color=BG_CARD,
                                      corner_radius=6, border_width=1,
                                      border_color=BORDER_GRAY)
        self.log_frame.grid(row=1, column=0, sticky="nsew", padx=25,
                            pady=(12, 25))
        self.log_frame.grid_rowconfigure(1, weight=1)
        self.log_frame.grid_columnconfigure(0, weight=1)

        header = ctk.CTkFrame(self.log_frame, fg_color=LOG_HEADER_BG, height=45)
        header.grid(row=0, column=0, sticky="ew", padx=2, pady=2)
        ctk.CTkLabel(header, text="SYSTEM EVENT LOG",
                     font=self.font(12, bold=True),
                     text_color=TEXT_DARK).pack(side="left", padx=15)
        self.btn_copy_log = ctk.CTkButton(
            header, text="COPY LOG", width=80, height=28, fg_color="transparent",
            border_width=1, border_color=BORDER_GRAY, text_color=TEXT_DARK,
            hover_color=INPUT_BG, font=self.font(11, bold=True),
            command=self._copy_log)
        self.btn_copy_log.pack(side="right", padx=15, pady=8)

        self.log_box = ctk.CTkTextbox(
            self.log_frame, fg_color="transparent",
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color=TEXT_DARK, state="disabled")
        self.log_box.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)

    # -- views ------------------------------------------------------------
    def _build_device_details_view(self):
        f = ctk.CTkFrame(self.op_window, fg_color="transparent")
        top = ctk.CTkFrame(f, fg_color="transparent")
        top.pack(fill="x", padx=20, pady=(16, 6))
        ctk.CTkLabel(top, text="DEVICE DETAILS", font=self.font(18, bold=True),
                     text_color=TEXT_DARK).pack(side="left")
        ctk.CTkButton(top, text="REFRESH", width=90,
                      command=lambda: self._run_threaded(self._cmd_load_details),
                      **{**self.primary_btn_kwargs, "height": 32}
                      ).pack(side="right")

        self.details_scroll = ctk.CTkScrollableFrame(f, fg_color="transparent")
        self.details_scroll.pack(fill="both", expand=True, padx=16, pady=(0, 12))
        ctk.CTkLabel(self.details_scroll, text="Press REFRESH to read the device.",
                     font=self.font(13), text_color=TEXT_SUB).pack(pady=30)
        self.card_views["device_details"] = f

    def _build_credentials_view(self):
        f = ctk.CTkFrame(self.op_window, fg_color="transparent")

        top = ctk.CTkFrame(f, fg_color="transparent")
        top.pack(fill="x", padx=20, pady=(16, 6))
        ctk.CTkLabel(top, text="SAVED CREDENTIALS", font=self.font(18, bold=True),
                     text_color=TEXT_DARK).pack(side="left")
        self.creds_subtitle = ctk.CTkLabel(top, text="", font=self.font(12),
                                           text_color=TEXT_SUB)
        self.creds_subtitle.pack(side="left", padx=(12, 0))

        pin_row = ctk.CTkFrame(f, fg_color="transparent")
        pin_row.pack(fill="x", padx=20, pady=(0, 8))
        ctk.CTkLabel(pin_row, text="PIN:", font=self.font(13, bold=True),
                     text_color=TEXT_DARK).pack(side="left", padx=(0, 8))
        self.creds_pin = ctk.CTkEntry(pin_row, placeholder_text="Enter PIN",
                                      show="*", width=200, height=36,
                                      fg_color=INPUT_BG, border_color=BORDER_GRAY,
                                      border_width=1, text_color=TEXT_DARK)
        self.creds_pin.pack(side="left")
        self.creds_pin.bind("<Return>", lambda _e: self._run_threaded(
            self._cmd_load_creds))
        self.btn_load_creds = ctk.CTkButton(
            pin_row, text="UNLOCK & LOAD", width=140,
            command=lambda: self._run_threaded(self._cmd_load_creds),
            **{**self.primary_btn_kwargs, "height": 36})
        self.btn_load_creds.pack(side="left", padx=(8, 0))

        self.creds_scroll = ctk.CTkScrollableFrame(f, fg_color="transparent")
        self.creds_scroll.pack(fill="both", expand=True, padx=16, pady=(0, 12))
        # Row registry (cred_id_b64 -> row widget) enables diff-based updates:
        # a delete destroys only the affected row instead of rebuilding the list.
        self._cred_rows: dict[str, ctk.CTkFrame] = {}
        self._creds_placeholder = ctk.CTkLabel(
            self.creds_scroll,
            text="Enter your token PIN and choose Unlock & Load.",
            font=self.font(13), text_color=TEXT_SUB)
        self._creds_placeholder.pack(pady=30)
        self.card_views["credentials"] = f

    def _show_about_popup(self):
        popup = HirschToplevel(self)
        popup.title("About")
        popup.geometry("380x260")
        popup.resizable(False, False)
        popup.configure(fg_color=BG_CARD)
        popup.grab_set()

        ctk.CTkFrame(popup, height=6, fg_color=BRAND_GREEN,
                     corner_radius=0).pack(fill="x")
        body = ctk.CTkFrame(popup, fg_color="white")
        body.pack(fill="both", expand=True)

        logo = create_logo_ctkimage()
        if logo is not None:
            ctk.CTkLabel(body, image=logo, text="").pack(pady=(28, 8))
        ctk.CTkLabel(body, text=APP_NAME, font=self.font(15, bold=True),
                     text_color=TEXT_DARK).pack()
        ctk.CTkLabel(body, text=f"Version {APP_VERSION}", font=self.font(12),
                     text_color=TEXT_SUB).pack(pady=(2, 0))
        ctk.CTkLabel(body, text="© 2026 All rights reserved.",
                     font=self.font(10), text_color=TEXT_SUB).pack(pady=(2, 0))
        ctk.CTkButton(
            body, text="CLOSE", width=100, height=34,
            fg_color=BRAND_MIDNIGHT, text_color="white",
            hover_color=BRAND_GREEN, font=self.font(12, bold=True),
            command=popup.destroy).pack(pady=(18, 0))

    # -- watchdog ---------------------------------------------------------
    def _on_device_removed(self):
        if self._device_removed:
            return
        self._device_removed = True
        self._pin = None
        if sys.platform.startswith("win"):
            ctypes.windll.user32.MessageBoxW(
                0, "Hirsch device has been disconnected.\n\n"
                   "The application will now close.",
                "Device Disconnected", 0x10)
        self.destroy()

    def _start_disconnect_watchdog(self, interval=3):
        def watchdog():
            while True:
                time.sleep(interval)
                if not is_reader_present(self.instance_id):
                    self.after(0, self._on_device_removed)
                    return
        threading.Thread(target=watchdog, daemon=True).start()

    # -- UI logic ---------------------------------------------------------
    def select_view(self, name):
        for btn in self.nav_buttons.values():
            btn.configure(text_color=TEXT_DARK)
        if name in self.nav_buttons:
            self.nav_buttons[name].configure(text_color=BRAND_GREEN)
        for fr in self.card_views.values():
            fr.place_forget()
        self.card_views[name].place(relx=0, rely=0, relwidth=1, relheight=1)
        self.safe_log(f"SYSTEM: View switched: {name.upper()}")

    def _copy_log(self):
        log_text = self.log_box.get("1.0", "end-1c")
        if log_text.strip():
            self.clipboard_clear()
            self.clipboard_append(log_text)
            self.btn_copy_log.configure(text="COPIED!")
            self.after(2000, lambda: self.btn_copy_log.configure(text="COPY LOG"))

    def _copy_aaguid(self, value):
        self.clipboard_clear()
        self.clipboard_append(value)
        self.btn_copy_aaguid.configure(text="COPIED!")
        self.after(2000, lambda: self.btn_copy_aaguid.configure(text="COPY"))
        self.safe_log("SYSTEM: AAGUID copied to clipboard.")

    def log_event(self, msg, max_lines=200):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"[{ts}] {msg}\n")
        self._log_lines += 1
        if self._log_lines > max_lines:      # tracked counter, no index parse
            self.log_box.delete("1.0", "2.0")
            self._log_lines -= 1
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    # -- thread-safe GUI helpers -----------------------------------------
    def safe_log(self, msg):
        self.after(0, lambda: self.log_event(msg))

    def safe_toggle_btn(self, btn, state):
        self.after(0, lambda: btn.configure(state=state))

    def _run_threaded(self, target_func):
        threading.Thread(target=target_func, daemon=True).start()

    # -- commands ---------------------------------------------------------
    def _cmd_load_details(self):
        self.safe_log("OPERATION: Reading full device info...")
        try:
            transport, info, retries = get_device_status()
        except Exception as e:
            self.safe_log(f"ERROR: Device details failed - {e}")
            self.after(0, lambda: messagebox.showerror(
                APP_NAME, f"Could not read device:\n\n{e}"))
            return
        self.after(0, lambda: self._render_details(transport, info, retries))

    def _render_details(self, transport, info, retries):
        for w in self.details_scroll.winfo_children():
            w.destroy()
        s = self.details_scroll

        def section(title):
            ctk.CTkLabel(s, text=title, font=self.font(12, bold=True),
                         text_color=TEXT_SUB, anchor="w").pack(fill="x",
                                                               pady=(12, 4))

        def chips(values):
            rowf, per_row, count = None, 4, 0
            for v in values:
                if count % per_row == 0:
                    rowf = ctk.CTkFrame(s, fg_color="transparent")
                    rowf.pack(fill="x", pady=2)
                chip = ctk.CTkFrame(rowf, corner_radius=12, fg_color=INPUT_BG,
                                    border_width=1, border_color=BORDER_GRAY)
                chip.pack(side="left", padx=(0, 6))
                ctk.CTkLabel(chip, text=str(v), font=self.font(12),
                             text_color=TEXT_DARK).pack(padx=10, pady=3)
                count += 1

        def kv(label, value):
            rowf = ctk.CTkFrame(s, fg_color="transparent")
            rowf.pack(fill="x", pady=1)
            ctk.CTkLabel(rowf, text=label, font=self.font(13),
                         text_color=TEXT_SUB, anchor="w").pack(side="left")
            ctk.CTkLabel(rowf, text=str(value), font=self.font(13, bold=True),
                         text_color=TEXT_DARK, anchor="e").pack(side="right")

        kv("Transport", transport)
        if retries is not None:
            kv("PIN Attempts Remaining", retries)

        section("Versions")
        chips(info.versions or [])
        if info.extensions:
            section("Extensions")
            chips(info.extensions)

        section("AAGUID")
        h = info.aaguid.hex()
        aaguid = f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"
        box = ctk.CTkFrame(s, corner_radius=8, fg_color=INPUT_BG)
        box.pack(fill="x", pady=2)
        self.btn_copy_aaguid = ctk.CTkButton(
            box, text="COPY", width=70, height=28, fg_color="transparent",
            border_width=1, border_color=BORDER_GRAY, text_color=TEXT_DARK,
            hover_color=BG_CARD, font=self.font(11, bold=True),
            command=lambda v=aaguid: self._copy_aaguid(v))
        self.btn_copy_aaguid.pack(side="right", padx=10, pady=6)
        ctk.CTkLabel(box, text=aaguid, font=self.font(13),
                     text_color=TEXT_DARK).pack(side="left", fill="x",
                                                expand=True, padx=12, pady=6)

        section("Options")
        opts = info.options or {}
        for key, label in OPTION_LABELS:
            if key in opts:
                kv(label, "Yes" if opts[key] else "No")

        if info.algorithms:
            section("Supported Algorithms")
            chips([ALG_NAMES.get(a.get("alg"), str(a.get("alg")))
                   for a in info.algorithms])

        section("Limits")
        for label, value in [
            ("Max Message Size", info.max_msg_size),
            ("Max Credentials in List", info.max_creds_in_list),
            ("Max Credential ID Length", info.max_cred_id_length),
            ("Min PIN Length", info.min_pin_length),
            ("PIN/UV Auth Protocols",
             ", ".join(str(p) for p in (info.pin_uv_protocols or [])) or None),
            ("Firmware Version", info.firmware_version),
        ]:
            if value is not None:
                kv(label, value)

        self.safe_log("SYSTEM: Device details refreshed.")

    def _cmd_load_creds(self):
        pin = self.creds_pin.get() or (self._pin or "")
        if not pin:
            self.after(0, lambda: messagebox.showwarning(
                "Input Required", "Please enter your token PIN."))
            return
        self.safe_toggle_btn(self.btn_load_creds, "disabled")
        self.safe_log("OPERATION: Unlocking token and enumerating credentials...")
        try:
            session = CredManSession(pin)
            try:
                existing, remaining = session.metadata()
                data = session.enumerate_all()
            finally:
                session.close()
        except Exception as e:
            msg = str(e)
            self.safe_log(f"ERROR: Credential load failed - {msg}")
            if "Incorrect PIN" in msg:
                self._pin = None
            self.safe_toggle_btn(self.btn_load_creds, "normal")
            self.after(0, lambda: messagebox.showerror(
                APP_NAME, f"Could not load credentials:\n\n{msg}"))
            return

        self._pin = pin
        self.safe_log(f"SYSTEM: {existing} credential(s) stored, "
                      f"{remaining} slot(s) remaining.")
        self.after(0, lambda: self._render_creds(data, existing, remaining))
        self.safe_toggle_btn(self.btn_load_creds, "normal")

    def _render_creds(self, data, existing, remaining):
        """
        Diff-based reconcile against the current row registry:
          - load: every credential is new -> all rows built (chunked)
          - delete: one credential gone -> only its row destroyed, nothing rebuilt
        This replaces the old destroy-everything-and-rebuild path.
        """
        self.creds_pin.delete(0, "end")
        self.creds_subtitle.configure(
            text=f"{existing} credential(s) • {remaining} slot(s) remaining")

        flat = [{"rp_id": rp["rp_id"], **c} for rp in data for c in rp["creds"]]
        new_by_key = {rec["cred_id_b64"]: rec for rec in flat}

        if self._creds_placeholder is not None:
            self._creds_placeholder.destroy()
            self._creds_placeholder = None

        # Destroy rows whose credential is no longer present (delete path).
        for key in list(self._cred_rows.keys()):
            if key not in new_by_key:
                self._cred_rows.pop(key).destroy()

        if not new_by_key:
            self._creds_placeholder = ctk.CTkLabel(
                self.creds_scroll, text="No credentials stored on this key.",
                font=self.font(14), text_color=TEXT_SUB)
            self._creds_placeholder.pack(pady=40)
            return

        # Build only credentials that don't already have a row, in chunks so
        # the UI thread never freezes on a large list.
        to_add = [rec for key, rec in new_by_key.items()
                  if key not in self._cred_rows]
        self._build_rows_chunked(to_add)

    def _build_rows_chunked(self, recs, start=0, chunk=12):
        for rec in recs[start:start + chunk]:
            self._build_cred_row(rec)
        nxt = start + chunk
        if nxt < len(recs):
            self.after(1, lambda: self._build_rows_chunked(recs, nxt, chunk))

    def _build_cred_row(self, rec):
        # Flattened row: 5 widgets (frame + 4 labels) laid out with grid, vs the
        # old 8 (extra head/col wrapper frames). The detail panel is created
        # lazily on first expand, so collapsed rows cost nothing extra.
        bg, fg = avatar_colors(rec["rp_id"])
        row = ctk.CTkFrame(self.creds_scroll, corner_radius=10,
                           fg_color=INPUT_BG, cursor="hand2")
        row.pack(fill="x", pady=4)
        row.grid_columnconfigure(1, weight=1)

        avatar = ctk.CTkLabel(row, text=(rec["rp_id"][:1] or "?").upper(),
                              width=40, height=40, corner_radius=20,
                              fg_color=bg, text_color=fg,
                              font=self.font(16, bold=True))
        avatar.grid(row=0, column=0, rowspan=2, padx=(10, 12), pady=8)

        rp_txt = (rec["rp_id"] if len(rec["rp_id"]) <= 40
                  else rec["rp_id"][:39] + "…")
        rp_lbl = ctk.CTkLabel(row, text=rp_txt, font=self.font(15, bold=True),
                              text_color=TEXT_DARK, anchor="w")
        rp_lbl.grid(row=0, column=1, sticky="ew", pady=(8, 0))
        sub_lbl = ctk.CTkLabel(
            row, text=rec["display_name"] or rec["user_name"] or "—",
            font=self.font(13), text_color=TEXT_SUB, anchor="w")
        sub_lbl.grid(row=1, column=1, sticky="ew", pady=(0, 8))
        chev = ctk.CTkLabel(row, text="▸", font=self.font(15),
                            text_color=TEXT_SUB)
        chev.grid(row=0, column=2, rowspan=2, padx=8)

        state = {"open": False, "detail": None}

        def toggle(_e=None):
            if state["open"]:
                if state["detail"] is not None:
                    state["detail"].grid_forget()
                chev.configure(text="▸")
                state["open"] = False
                return
            if state["detail"] is None:
                d = ctk.CTkFrame(row, fg_color=BG_CARD, corner_radius=8)
                self._build_cred_detail(d, rec)
                state["detail"] = d
            state["detail"].grid(row=2, column=0, columnspan=3, sticky="ew",
                                 padx=8, pady=(0, 8))
            chev.configure(text="▾")
            state["open"] = True

        for w in (row, avatar, rp_lbl, sub_lbl, chev):
            w.bind("<Button-1>", toggle)

        self._cred_rows[rec["cred_id_b64"]] = row

    def _build_cred_detail(self, parent, rec):
        inner = ctk.CTkFrame(parent, fg_color="transparent")
        inner.pack(fill="x", padx=12, pady=10)

        def field(label, value):
            ctk.CTkLabel(inner, text=label, font=self.font(12),
                         text_color=TEXT_SUB, anchor="w").pack(fill="x")
            ctk.CTkLabel(inner, text=value, font=self.font(13),
                         text_color=TEXT_DARK, anchor="w", justify="left",
                         wraplength=560).pack(fill="x", pady=(0, 8))

        user_id_hex = ""
        try:
            user_id_hex = base64.b64decode(rec["user_id_b64"]).hex().upper()
        except Exception:
            pass
        field("Display name", rec["display_name"] or "—")
        field("Username", rec["user_name"] or "—")
        field("User ID", user_id_hex or "—")
        field("Credential ID", rec["cred_id_bytes"].hex().upper())
        field("Protect", PROTECT_NAMES.get(rec["protect"], str(rec["protect"])))

        ctk.CTkButton(
            inner, text="\U0001F5D1  Delete credential", width=0, height=34,
            fg_color="transparent", hover_color="#F3DED9", text_color=DANGER,
            font=self.font(13, bold=True),
            command=lambda: self._confirm_delete(rec)).pack(anchor="w")

    def _confirm_delete(self, rec):
        if not messagebox.askyesno(
                "Delete credential?",
                f"This will permanently delete the passkey for "
                f"{rec['rp_id']}.\n\nYou won't be able to sign in to this site "
                f"with this security key anymore.", icon="warning",
                parent=self):
            return
        self._run_threaded(lambda: self._cmd_delete(rec))

    def _cmd_delete(self, rec):
        self.safe_log(f"OPERATION: Deleting credential for {rec['rp_id']}...")
        try:
            session = CredManSession(self._pin)
            try:
                session.delete_credential(rec["cred_id_bytes"])
                existing, remaining = session.metadata()
                data = session.enumerate_all()
            finally:
                session.close()
        except Exception as e:
            self.safe_log(f"ERROR: Delete failed - {e}")
            self.after(0, lambda: messagebox.showerror(
                APP_NAME, f"Delete failed:\n\n{e}"))
            return
        self.safe_log("SUCCESS: Credential deleted.")
        self.after(0, lambda: self._render_creds(data, existing, remaining))

    def _on_close(self):
        self._pin = None
        self.destroy()


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------
def main():
    # Auto-elevate: FIDO HID access on Windows requires Administrator.
    if not is_admin() and sys.platform.startswith("win"):
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

    reader_name, instance_id = discover_hirsch_reader()
    if not instance_id:
        if sys.platform.startswith("win"):
            ctypes.windll.user32.MessageBoxW(
                0, "No Hirsch device detected.\n\nPlease connect your Hirsch "
                   "reader or key and try again.\n\n"
                   "This application requires a Hirsch reader (VID_04E6).",
                "Hardware Not Found", 0x10)
        else:
            print("No Hirsch device detected.")
        sys.exit(1)

    app = SecureFidoApp(instance_id=instance_id)
    app.log_event(f"SYSTEM: Hardware verified - {reader_name} [{instance_id}]")
    app.mainloop()


if __name__ == "__main__":
    main()
