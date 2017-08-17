# coding: utf-8

from __future__ import absolute_import

import sys
import os
import platform

is_windows = (bool(platform.win32_ver()[0]) or
             (sys.platform in ("win32", "cygwin")) or
             (sys.platform == "cli" and os.name in ("nt", "ce")),
             (os.name == "java" and
              "windows" in platform.java_ver()[3][0].lower()))
is_linux   = sys.platform.startswith("linux")
is_osx     = (sys.platform == "darwin")
is_android = False
is_posix   = (os.name == "posix")

del sys, os, platform

defined = lambda varname: varname in locals() or varname in globals()

if is_windows:
    from ._windows import DLL_PATH, DLL, CFUNC, dlclose, timeval
elif is_linux:
    from ._linux   import DLL_PATH, DLL, CFUNC, dlclose, timeval
elif is_osx:
    from ._osx     import DLL_PATH, DLL, CFUNC, dlclose, timeval
else:
    raise ImportError("unsupported platform")

# eof
