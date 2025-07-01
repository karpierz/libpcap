# flake8-in-file-ignores: noqa: E305,E402,F401,N813,N814

# Copyright (c) 2016 Adam Karpierz
# SPDX-License-Identifier: BSD-3-Clause

import sys
import os
import ctypes as ct
from ctypes.util import find_library

this_dir = os.path.dirname(os.path.abspath(__file__))
is_32bit = (sys.maxsize <= 2**32)
arch     = "x86" if is_32bit else "x64"
arch_dir = os.path.join(this_dir, arch)

def _DLL(*args, **kwargs):
    import os
    from ctypes import WinDLL
    with os.add_dll_directory(os.path.dirname(args[0])):
        return WinDLL(*args, **kwargs)

found = False
try:
    from ...__config__ import config
    LIBPCAP = config.get("LIBPCAP", None)
    del config
    if LIBPCAP is None or LIBPCAP in ("", "None"):
        raise ImportError()
except ImportError:
    if find_library(os.path.join("npcap", "wpcap")):
        LIBPCAP = "npcap"
    else:
        LIBPCAP = find_library("wpcap")
        if not LIBPCAP:
            raise OSError("Cannot find wpcap.dll library") from None
        found = True
        from ctypes import WinDLL as DLL
else:
    DLL = _DLL

if LIBPCAP == "npcap":
    LIBPCAP = find_library(os.path.join("npcap", "wpcap"))
    if not LIBPCAP:
        raise OSError("Cannot find npcap/wpcap.dll library")
    found = True
    npcap_dir = os.path.dirname(LIBPCAP)
    ct.windll.kernel32.SetDllDirectoryA(npcap_dir.encode("utf-8"))
    ct.cdll.LoadLibrary(os.path.join(npcap_dir, "Packet.dll"))
    del npcap_dir
    DLL = _DLL

if found or os.path.isabs(LIBPCAP):
    DLL_PATH = LIBPCAP
elif LIBPCAP == "wpcap":
    DLL_PATH = os.path.join(arch_dir, LIBPCAP, "wpcap.dll")
elif LIBPCAP == "tcpdump":
    DLL_PATH = os.path.join(arch_dir, LIBPCAP, "msys-pcap-1.dll")
else:
    raise ValueError("Improper value of the LIBPCAP configuration variable: {}".format(LIBPCAP))

try:
    from _ctypes import FreeLibrary as dlclose
except ImportError:
    dlclose = lambda handle: 0
from ctypes import CFUNCTYPE as CFUNC

time_t = ct.c_uint64

# Winsock doesn't have this POSIX type; it's used for the
# tv_usec value of struct timeval.
suseconds_t = ct.c_long

# Taken from the file <winsock.h>
#
# struct timeval {
#     long tv_sec;   /* seconds */
#     long tv_usec;  /* and microseconds */
# };

class timeval(ct.Structure):
    _fields_ = [
    ("tv_sec",  ct.c_long),    # seconds
    ("tv_usec", suseconds_t),  # microseconds
]

# Taken from the file libpcap's "socket.h"

# Some minor differences between sockets on various platforms.
# We include whatever sockets are needed for Internet-protocol
# socket access.

# In Winsock, a socket handle is of type SOCKET.
SOCKET = ct.c_uint

# In Winsock, the error return if socket() fails is INVALID_SOCKET.
INVALID_SOCKET = SOCKET(-1).value

# Winsock doesn't have this UN*X type; it's used in the UN*X
# sockets API.
socklen_t = ct.c_int

class sockaddr(ct.Structure):
    _fields_ = [
    ("sa_family", ct.c_short),
    ("__pad1",    ct.c_ushort),
    ("ipv4_addr", ct.c_byte * 4),
    ("ipv6_addr", ct.c_byte * 16),
    ("__pad2",    ct.c_ulong),
]

# POSIX.1g specifies this type name for the `sa_family' member.
sa_family_t = ct.c_short

# Type to represent a port.
in_port_t = ct.c_ushort

# IPv4 AF_INET sockets:

class in_addr(ct.Union):
    _fields_ = [
    ("s_addr", ct.c_uint32),  # ct.c_ulong
]

class sockaddr_in(ct.Structure):
    _fields_ = [
    ("sin_family", sa_family_t),      # e.g. AF_INET, AF_INET6
    ("sin_port",   in_port_t),        # e.g. htons(3490)
    ("sin_addr",   in_addr),          # see struct in_addr, above
    ("sin_zero",   (ct.c_char * 8)),  # padding, zero this if you want to
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
    ("sin6_port",     in_port_t),    # port number, Network Byte Order
    ("sin6_flowinfo", ct.c_ulong),   # IPv6 flow information
    ("sin6_addr",     in6_addr),     # IPv6 address
    ("sin6_scope_id", ct.c_ulong),   # Scope ID
]
