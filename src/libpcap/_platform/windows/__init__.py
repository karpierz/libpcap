# flake8-in-file-ignores: noqa: E305,E402,F401,F811,N813,N814

# Copyright (c) 2016 Adam Karpierz
# SPDX-License-Identifier: BSD-3-Clause

from typing import Any
import os
import platform
from pathlib import Path
import ctypes
from ctypes.util import find_library

from utlx import module_path
from utlx.platform import arch
from utlx.platform.capi import DLL as _DLL, dlclose
from ctypes import CFUNCTYPE as CFUNC
from utlx.platform.windows import winapi

__all__ = ('DLL_PATH', 'DLL', 'dlclose', 'CFUNC', 'winapi')

this_dir = module_path()
arch_dir = this_dir/(arch or "")

def DLL(*args: Any, **kwargs: Any) -> _DLL:
    import os
    with os.add_dll_directory(os.path.dirname(args[0])):
        return _DLL(*args, **kwargs)

found = False
try:
    from ...__config__ import config  # type: ignore[attr-defined]
    LIBPCAP = config.get("LIBPCAP", None)
    del config
    if LIBPCAP is None or LIBPCAP in ("", "None"):
        raise ImportError()
except ImportError:
    if find_library(os.path.join("npcap", "wpcap")):
        LIBPCAP = "npcap"
    else:
        LIBPCAP = find_library("wpcap")
        if not LIBPCAP:
            raise OSError("Cannot find wpcap.dll library") from None
        found = True
        DLL = _DLL

if LIBPCAP == "npcap":
    LIBPCAP = find_library(os.path.join("npcap", "wpcap"))
    if not LIBPCAP:
        raise OSError("Cannot find npcap/wpcap.dll library")
    found = True
    npcap_dir = os.path.dirname(LIBPCAP)
    ctypes.windll.kernel32.SetDllDirectoryA(npcap_dir.encode("utf-8"))
    ctypes.cdll.LoadLibrary(os.path.join(npcap_dir, "Packet.dll"))
    del npcap_dir

if found or os.path.isabs(LIBPCAP):
    DLL_PATH = Path(LIBPCAP)
elif LIBPCAP == "wpcap":
    DLL_PATH = arch_dir/LIBPCAP/"wpcap.dll"
elif LIBPCAP == "tcpdump":
    DLL_PATH = arch_dir/LIBPCAP/"msys-pcap-1.dll"
else:
    raise ValueError("Improper value of the LIBPCAP "
                     f"configuration variable: {LIBPCAP}")
