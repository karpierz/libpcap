# Copyright (c) 2016 Adam Karpierz
# SPDX-License-Identifier: BSD-3-Clause

import sys
import os
import ctypes as ct

from ._platform import *  # noqa

def defined(varname, __getframe=sys._getframe):
    frame = __getframe(1)
    return varname in frame.f_locals or varname in frame.f_globals

def from_oid(oid, __cast=ct.cast, __py_object=ct.py_object):
    return __cast(oid, __py_object).value if oid else None

del sys, os, ct

if is_windows:  # noqa: F405
    from ._windows import (DLL_PATH, DLL, dlclose, CFUNC,
                           time_t, timeval,
                           SOCKET, INVALID_SOCKET, sockaddr,
                           in_addr, sockaddr_in,
                           in6_addr, sockaddr_in6)  # noqa: F401
elif is_linux:  # noqa: F405
    from ._linux   import (DLL_PATH, DLL, dlclose, CFUNC,
                           time_t, timeval,
                           SOCKET, INVALID_SOCKET, sockaddr,
                           in_addr, sockaddr_in,
                           in6_addr, sockaddr_in6)  # noqa: F401
elif is_macos:  # noqa: F405
    from ._macos   import (DLL_PATH, DLL, dlclose, CFUNC,
                           time_t, timeval,
                           SOCKET, INVALID_SOCKET, sockaddr,
                           in_addr, sockaddr_in,
                           in6_addr, sockaddr_in6)  # noqa: F401
else:
    raise ImportError("unsupported platform")
