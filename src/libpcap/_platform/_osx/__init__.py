# Copyright (c) 2016-2022, Adam Karpierz
# Licensed under the BSD license
# https://opensource.org/licenses/BSD-3-Clause

import sys
import os
from functools import partial
import ctypes as ct
from ctypes.util import find_library

this_dir = os.path.dirname(os.path.abspath(__file__))
is_32bit = (sys.maxsize <= 2**32)
arch     = "x86" if is_32bit else "x64"
arch_dir = os.path.join(this_dir, arch)

raise NotImplementedError("This OS is not supported yet!")

try:
    from ...__config__ import config
    LIBPCAP = config.get("LIBPCAP", None)
    del config
    if LIBPCAP is None or LIBPCAP in ("", "None"):
        raise ImportError()
except ImportError:
    LIBPCAP = "tcpdump"  # !!! temporary? !!!

if os.path.isabs(LIBPCAP):
    DLL_PATH = LIBPCAP
else:
    DLL_PATH = os.path.join(arch_dir, LIBPCAP, "libpcap-1.0.dylib")

from ctypes  import CDLL as DLL
from _ctypes import dlclose
from ctypes  import CFUNCTYPE as CFUNC

DLL = partial(DLL, mode=ct.RTLD_GLOBAL)

# X32 kernel interface is 64-bit.
if False:#if defined __x86_64__ && defined __ILP32__
    # quad_t is also 64 bits.
    time_t = suseconds_t = ct.c_longlong
else:
    time_t = suseconds_t = ct.c_long
#endif

# Taken from the file <sys/time.h>
#include <time.h>
#
# struct timeval {
#     time_t      tv_sec;   /* Seconds. */
#     suseconds_t tv_usec;  /* Microseconds. */
# };

class timeval(ct.Structure):
    _fields_ = [
    ("tv_sec",  time_t),       # seconds
    ("tv_usec", suseconds_t),  # microseconds
]
