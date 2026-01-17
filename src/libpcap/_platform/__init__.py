# flake8-in-file-ignores: noqa: F403,F405

# Copyright (c) 2016 Adam Karpierz
# SPDX-License-Identifier: BSD-3-Clause

__all__ = (
    'is_windows', 'is_linux', 'is_macos', 'defined',
    'DLL_PATH', 'DLL', 'dlclose', 'CFUNC',
    'limits', 'time_t', 'timeval',
    'SOCKET', 'INVALID_SOCKET', 'sockaddr',
    'in_addr', 'sockaddr_in', 'in6_addr', 'sockaddr_in6',
)

from utlx import defined
from utlx.platform import *
from utlx.platform import limits
if is_windows:  # pragma: no cover
    from .windows import DLL_PATH, DLL, dlclose, CFUNC
elif is_linux:  # pragma: no cover
    from .linux   import DLL_PATH, DLL, dlclose, CFUNC
elif is_macos:  # pragma: no cover
    from .macos   import DLL_PATH, DLL, dlclose, CFUNC
else:  # pragma: no cover
    raise ImportError("Unsupported platform")
if not DLL_PATH.exists():
    raise ImportError(f"Shared library not found: {DLL_PATH}")

from utlx.platform.capi import (
    time_t, timeval,
    SOCKET, INVALID_SOCKET, sockaddr,
    in_addr,  sockaddr_in, in6_addr, sockaddr_in6,
)
