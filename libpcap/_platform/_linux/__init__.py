# Copyright (c) 2016-2017, Adam Karpierz
# Licensed under the BSD license
# https://opensource.org/licenses/BSD-3-Clause

import sys
import os

this_dir = os.path.dirname(os.path.abspath(__file__))
is_py32bit = sys.maxsize <= 2**32

DLL_PATH = os.path.join(this_dir, "x86" if is_py32bit else "x64", "libpcap-1.0.so")

import ctypes as ct
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

class sockaddr(ct.Structure): 
    _fields_ = [
    ("sa_family", ct.c_short), 
    ("__pad1",    ct.c_ushort), 
    ("ipv4_addr", ct.c_byte * 4), 
    ("ipv6_addr", ct.c_byte * 16), 
    ("__pad2",    ct.c_ulong),
] 
