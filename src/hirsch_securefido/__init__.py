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
Hirsch SecureFIDO Device Config
===============================
macOS command-line tool for the *device configuration* subset of the Hirsch
SecureFIDO toolset:

    * device info      - read authenticator info, options, limits, PIN retries
    * set-pin          - set the initial PIN on a factory-fresh token
    * change-pin       - change an existing PIN
    * reset            - factory reset (destroys all credentials and the PIN)

Credential enumeration/deletion is deliberately NOT part of this package.
"""

from __future__ import annotations

from .device import (
    ALLOWED_HID_VIDS,
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
    set_pin,
)

__version__ = "1.0.0"
__app_name__ = "Hirsch SecureFIDO Device Config"

__all__ = [
    "ALLOWED_HID_VIDS",
    "DeviceError",
    "DeviceInfo",
    "DeviceNotFoundError",
    "PinBlockedError",
    "PinError",
    "ResetNotAllowedError",
    "UnsupportedOperationError",
    "change_pin",
    "factory_reset",
    "get_device_info",
    "list_devices",
    "set_pin",
    "__version__",
    "__app_name__",
]
