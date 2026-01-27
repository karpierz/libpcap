# flake8-in-file-ignores: noqa: E305,E402,F401

# Copyright (c) 2016 Adam Karpierz
# SPDX-License-Identifier: BSD-3-Clause

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

try:
    from ...__config__ import config  # type: ignore[attr-defined]
    config_var = config.get("LIBPCAP")
    del config
    if config_var in (None, "", "None"): raise ImportError()
except ImportError:
    dll_path = find_library("pcap")
    if not dll_path:
        raise OSError("Cannot find libpcap.so library") from None
    DLL_PATH = Path(dll_path)
else:
    if config_var == "tcpdump":
        DLL_PATH = arch_dir/config_var/"libpcap.so"
    elif Path(config_var).is_absolute():
        DLL_PATH = Path(config_var)
    else:
        raise ValueError("Improper value of the LIBPCAP "
                         f"configuration variable: {config_var}")

DLL = partial(_DLL, mode=ctypes.RTLD_GLOBAL)
