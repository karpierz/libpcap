# coding: utf-8

import sys
import os

this_dir = os.path.dirname(os.path.abspath(__file__))
is_py32bit = sys.maxsize <= 2**32

DLL_PATH = os.path.join(this_dir, "win32" if is_py32bit else "x64", "libpcap-1.0.so")

from ctypes  import CDLL      as DLL
from ctypes  import CFUNCTYPE as CFUNC
from _ctypes import dlclose

# Taken from the file sys/time.h.
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
