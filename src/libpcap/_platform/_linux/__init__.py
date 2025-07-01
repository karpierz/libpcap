# flake8-in-file-ignores: noqa: E305,E402,F401

# Copyright (c) 2016 Adam Karpierz
# SPDX-License-Identifier: BSD-3-Clause

import sys
import os
from functools import partial
import ctypes as ct
from ctypes.util import find_library

this_dir = os.path.dirname(os.path.abspath(__file__))
is_32bit = (sys.maxsize <= 2**32)
arch     = "x86" if is_32bit else "x64"
arch_dir = os.path.join(this_dir, arch)

found = False
try:
    from ...__config__ import config
    LIBPCAP = config.get("LIBPCAP", None)
    del config
    if LIBPCAP is None or LIBPCAP in ("", "None"):
        raise ImportError()
except ImportError:
    LIBPCAP = find_library("pcap")
    if not LIBPCAP:
        raise OSError("Cannot find libpcap.so library") from None
    found = True

if found or os.path.isabs(LIBPCAP):
    DLL_PATH = LIBPCAP
elif LIBPCAP == "tcpdump":
    DLL_PATH = os.path.join(arch_dir, LIBPCAP, "libpcap.so")
else:
    raise ValueError("Improper value of the LIBPCAP configuration variable: {}".format(LIBPCAP))

from ctypes  import CDLL as DLL
from _ctypes import dlclose
from ctypes  import CFUNCTYPE as CFUNC

DLL = partial(DLL, mode=ct.RTLD_GLOBAL)

# X32 kernel interface is 64-bit.
if False:  # if defined __x86_64__ && defined __ILP32__
    # quad_t is also 64 bits.
    time_t = suseconds_t = ct.c_longlong
else:
    time_t = suseconds_t = ct.c_long
# endif

# Taken from the file <sys/time.h>
# #include <time.h>
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

# Taken from the file libpcap's "socket.h"

# Some minor differences between sockets on various platforms.
# We include whatever sockets are needed for Internet-protocol
# socket access.

# In UN*X, a socket handle is a file descriptor, and therefore
# a signed integer.
SOCKET = ct.c_int

# In UN*X, the error return if socket() fails is -1.
INVALID_SOCKET = SOCKET(-1).value

class sockaddr(ct.Structure):
    _fields_ = [
    ("sa_family", ct.c_short),
    ("__pad1",    ct.c_ushort),
    ("ipv4_addr", ct.c_byte * 4),
    ("ipv6_addr", ct.c_byte * 16),
    ("__pad2",    ct.c_ulong),
]

# POSIX.1g specifies this type name for the `sa_family' member.
sa_family_t = ct.c_ushort

# Type to represent a port.
in_port_t = ct.c_uint16

# IPv4 AF_INET sockets:

class in_addr(ct.Structure):
    _fields_ = [
    ("s_addr", ct.c_uint32),
]

class sockaddr_in(ct.Structure):
    _fields_ = [
    ("sin_family", sa_family_t),  # e.g. AF_INET, AF_INET6
    ("sin_port",   in_port_t),    # Port number.
    ("sin_addr",   in_addr),      # Internet address.
    ("sin_zero",   (ct.c_ubyte    # Pad to size of `struct sockaddr'.
                    * (ct.sizeof(sockaddr)
                       - ct.sizeof(sa_family_t)
                       - ct.sizeof(in_port_t)
                       - ct.sizeof(in_addr)))),
]

# IPv6 AF_INET6 sockets:

class in6_addr(ct.Union):
    _fields_ = [
    ("s6_addr",   (ct.c_uint8 * 16)),
    ("s6_addr16", (ct.c_uint16 * 8)),
    ("s6_addr32", (ct.c_uint32 * 4)),
]

class sockaddr_in6(ct.Structure):
    _fields_ = [
    ("sin6_family",   sa_family_t),  # address family, AF_INET6
    ("sin6_port",     in_port_t),    # Transport layer port #
    ("sin6_flowinfo", ct.c_uint32),  # IPv6 flow information
    ("sin6_addr",     in6_addr),     # IPv6 address
    ("sin6_scope_id", ct.c_uint32),  # IPv6 scope-id
]
