# flake8-in-file-ignores: noqa: E305,E402,F401

# Copyright (c) 2016 Adam Karpierz
# SPDX-License-Identifier: BSD-3-Clause

import os
import platform
from pathlib import Path
from functools import partial
import ctypes
from ctypes.util import find_library

from utlx import module_path
from utlx.platform import arch
from utlx.platform.capi import DLL as _DLL, dlclose, CFUNC

__all__ = ('DLL_PATH', 'DLL', 'dlclose', 'CFUNC')

this_dir = module_path()
arch_dir = this_dir/(arch or "")

found = False
try:
    from ...__config__ import config  # type: ignore[attr-defined]
    LIBPCAP = config.get("LIBPCAP", None)
    del config
    if LIBPCAP is None or LIBPCAP in ("", "None"):
        raise ImportError()
except ImportError:
    LIBPCAP = find_library("pcap")
    if not LIBPCAP:
        raise OSError("Cannot find libpcap.so library") from None
    found = True

if found or os.path.isabs(LIBPCAP):
    DLL_PATH = Path(LIBPCAP)
elif LIBPCAP == "tcpdump":
    DLL_PATH = arch_dir/LIBPCAP/"libpcap.so"
else:
    raise ValueError("Improper value of the LIBPCAP "
                     f"configuration variable: {LIBPCAP}")

DLL = partial(_DLL, mode=ctypes.RTLD_GLOBAL)
