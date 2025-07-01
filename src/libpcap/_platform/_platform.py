# flake8-in-file-ignores: noqa: A005

# Copyright (c) 1994 Adam Karpierz
# SPDX-License-Identifier: Zlib

import sys
import os
import platform

is_windows = (bool(platform.win32_ver()[0])
              or (sys.platform in ("win32", "cygwin", "msys"))
              or (sys.platform == "cli" and os.name in ("nt", "ce"))
              or (os.name == "java"
                  and "windows" in platform.java_ver()[3][0].lower()))
is_wsl     = ("microsoft-standard" in platform.uname().release)
is_cygwin  = (sys.platform == "cygwin")
is_msys    = (sys.platform == "msys")
is_linux   = sys.platform.startswith("linux")
is_macos   = sys.platform.startswith("darwin")
is_bsd     = sys.platform.startswith(("freebsd", "openbsd", "netbsd"))
is_sunos   = sys.platform.startswith(("sunos", "solaris"))
is_aix     = sys.platform.startswith("aix")
is_android = hasattr(sys, "getandroidapilevel")
is_posix   = (os.name == "posix")
is_32bit   = (sys.maxsize <= 2**32)
is_ucs2    = (sys.maxunicode < 0x10FFFF)
is_cpython = (platform.python_implementation().lower() == "cpython")
is_pypy    = (platform.python_implementation().lower() == "pypy")
is_ironpython = (platform.python_implementation().lower() == "ironpython"
                 or "cli" in (platform.system().lower(), sys.platform))

del sys, os, platform
