# Copyright (c) 2016 Adam Karpierz
# SPDX-License-Identifier: BSD-3-Clause

import sys
import os
import ctypes as ct

from ._platform import is_windows, is_linux, is_macos

def defined(varname, __getframe=sys._getframe):
    frame = __getframe(1)
    return varname in frame.f_locals or varname in frame.f_globals

def from_oid(oid, __cast=ct.cast, __py_object=ct.py_object):
    return __cast(oid, __py_object).value if oid else None

del sys, os, ct

if is_windows:
    from ._windows import DLL_PATH, DLL, dlclose, CFUNC
    from ._windows import time_t, timeval
    from ._windows import (SOCKET, INVALID_SOCKET,
                           sockaddr, in_addr, sockaddr_in, in6_addr, sockaddr_in6)
elif is_linux:
    from ._linux   import DLL_PATH, DLL, dlclose, CFUNC
    from ._linux   import time_t, timeval
    from ._linux   import (SOCKET, INVALID_SOCKET,
                           sockaddr, in_addr, sockaddr_in, in6_addr, sockaddr_in6)
elif is_macos:
    from ._macos   import DLL_PATH, DLL, dlclose, CFUNC
    from ._macos   import time_t, timeval
    from ._macos   import (SOCKET, INVALID_SOCKET,
                           sockaddr, in_addr, sockaddr_in, in6_addr, sockaddr_in6)
else:
    raise ImportError("unsupported platform")
