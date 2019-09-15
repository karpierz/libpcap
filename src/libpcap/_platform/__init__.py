# Copyright (c) 2016-2019, Adam Karpierz
# Licensed under the BSD license
# http://opensource.org/licenses/BSD-3-Clause

from __future__ import absolute_import

import sys
import os
import platform

is_windows = (bool(platform.win32_ver()[0]) or
              (sys.platform in ("win32", "cygwin")) or
              (sys.platform == "cli" and os.name in ("nt", "ce")) or
              (os.name == "java" and
               "windows" in platform.java_ver()[3][0].lower()))
is_linux   = sys.platform.startswith("linux")
is_osx     = (sys.platform == "darwin")
is_android = False
is_posix   = (os.name == "posix")
is_32bit   = (sys.maxsize <= 2**32)

def defined(varname, _getframe=sys._getframe):
    frame = _getframe(1)
    return varname in frame.f_locals or varname in frame.f_globals

del sys, os, platform

if is_windows:
    from ._windows import DLL_PATH, DLL, CFUNC, dlclose
    from ._windows import SOCKET, INVALID_SOCKET, timeval, sockaddr, sockaddr_in, sockaddr_in6
elif is_linux:
    from ._linux   import DLL_PATH, DLL, CFUNC, dlclose
    from ._linux   import SOCKET, INVALID_SOCKET, timeval, sockaddr, sockaddr_in, sockaddr_in6
elif is_osx:
    from ._osx     import DLL_PATH, DLL, CFUNC, dlclose
    from ._osx     import SOCKET, INVALID_SOCKET, timeval, sockaddr, sockaddr_in, sockaddr_in6
else:
    raise ImportError("unsupported platform")
