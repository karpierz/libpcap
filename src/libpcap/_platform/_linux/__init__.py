# Copyright (c) 2016-2019, Adam Karpierz
# Licensed under the BSD license
# http://opensource.org/licenses/BSD-3-Clause

import sys
import os
from functools import partial
import ctypes as ct

this_dir = os.path.dirname(os.path.abspath(__file__))
is_32bit = (sys.maxsize <= 2**32)

try:
    from ...__config__ import LIBPCAP
except ImportError:
    DLL_PATH = "???"
else:
    if os.path.isabs(LIBPCAP):
        DLL_PATH = LIBPCAP
    else:
        arch = "x86" if is_32bit else "x64"
        DLL_PATH = os.path.join(this_dir, arch + "_" + LIBPCAP, "libpcap-1.0.so")

from ctypes  import CDLL      as DLL
from ctypes  import CFUNCTYPE as CFUNC
from _ctypes import dlclose

DLL = partial(DLL, mode=ct.RTLD_GLOBAL)

# X32 kernel interface is 64-bit.
if False:#if defined __x86_64__ && defined __ILP32__
    # quad_t is also 64 bits.
    time_t = suseconds_t = ct.c_longlong
else:
    time_t = suseconds_t = ct.c_long
#endif

# Taken from the file libpcap's "socket.h"

# Some minor differences between sockets on various platforms.
# We include whatever sockets are needed for Internet-protocol
# socket access.

# In UN*X, a socket handle is a file descriptor, and therefore
# a signed integer.
SOCKET = ct.c_int

# In UN*X, the error return if socket() fails is -1.
INVALID_SOCKET = SOCKET(-1).value

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

class sockaddr(ct.Structure):
    _fields_ = [
    ("sa_family", ct.c_short),
    ("__pad1",    ct.c_ushort),
    ("ipv4_addr", ct.c_byte * 4),
    ("ipv6_addr", ct.c_byte * 16),
    ("__pad2",    ct.c_ulong),
]
