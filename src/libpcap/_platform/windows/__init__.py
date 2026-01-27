# flake8-in-file-ignores: noqa: E305,E402,F401,F811,N813,N814

# Copyright (c) 2016 Adam Karpierz
# SPDX-License-Identifier: BSD-3-Clause

from typing import Any
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

def _load_packet_dll(npcap_dir: Path) -> None:
    import ctypes
    ctypes.windll.kernel32.SetDllDirectoryA(str(npcap_dir).encode("utf-8"))
    ctypes.cdll.LoadLibrary(str(npcap_dir/"packet.dll"))

try:
    from ...__config__ import config  # type: ignore[attr-defined]
    config_var = config.get("LIBPCAP")
    del config
    if config_var in (None, "", "None"): raise ImportError()
except ImportError:
    dll_path = find_library(str(Path("npcap")/"wpcap"))
    if dll_path:  # npcap
        DLL_PATH = Path(dll_path)
        _load_packet_dll(DLL_PATH.parent)
    else:
        dll_path = find_library("wpcap")
        if dll_path:  # wpcap
            DLL_PATH = Path(dll_path)
            _load_packet_dll(DLL_PATH.parent)
        else:
            raise OSError("Cannot find npcap/wpcap.dll or wpcap.dll "
                          "library") from None
else:
    if config_var == "npcap":
        dll_path = find_library(str(Path("npcap")/"wpcap"))
        if not dll_path:
            raise OSError("Cannot find npcap/wpcap.dll library")
        DLL_PATH = Path(dll_path)
        _load_packet_dll(DLL_PATH.parent)
    elif config_var == "wpcap":
        DLL_PATH = arch_dir/config_var/"wpcap.dll"
        _load_packet_dll(DLL_PATH.parent)
    elif config_var == "tcpdump":
        DLL_PATH = arch_dir/config_var/"pcap.dll"
    elif Path(config_var).is_absolute():
        DLL_PATH = Path(config_var)
    else:
        raise ValueError("Improper value of the LIBPCAP "
                         f"configuration variable: {config_var}")
