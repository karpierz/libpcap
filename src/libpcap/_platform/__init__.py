# flake8-in-file-ignores: noqa: E305,F401,F403,F405

# Copyright (c) 2016 Adam Karpierz
# SPDX-License-Identifier: BSD-3-Clause

import sys
import os
import ctypes as ct

from ._platform import *

def defined(varname, __getframe=sys._getframe):
    frame = __getframe(1)
    return varname in frame.f_locals or varname in frame.f_globals

def from_oid(oid, __cast=ct.cast, __py_object=ct.py_object):
    return __cast(oid, __py_object).value if oid else None

del sys, os, ct

if is_windows:
    from ._windows import (DLL_PATH, DLL, dlclose, CFUNC,
                           time_t, timeval,
                           SOCKET, INVALID_SOCKET, sockaddr,
                           in_addr, sockaddr_in,
                           in6_addr, sockaddr_in6)
elif is_linux:
    from ._linux import (DLL_PATH, DLL, dlclose, CFUNC,
                         time_t, timeval,
                         SOCKET, INVALID_SOCKET, sockaddr,
                         in_addr, sockaddr_in,
                         in6_addr, sockaddr_in6)
elif is_macos:
    from ._macos import (DLL_PATH, DLL, dlclose, CFUNC,
                         time_t, timeval,
                         SOCKET, INVALID_SOCKET, sockaddr,
                         in_addr, sockaddr_in,
                         in6_addr, sockaddr_in6)
else:
    raise ImportError("unsupported platform")
