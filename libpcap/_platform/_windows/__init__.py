# Copyright (c) 2016-2017, Adam Karpierz
# Licensed under the BSD license
# https://opensource.org/licenses/BSD-3-Clause

import sys
import os

this_dir = os.path.dirname(os.path.abspath(__file__))
is_py32bit = sys.maxsize <= 2**32

DLL_PATH = "C:/Windows/System32/wpcap.dll"
DLL_PATH = os.path.join(this_dir, ("x86" if is_py32bit else "x64") + "_" + "wpcap", "wpcap.dll")

import ctypes as ct
from ctypes  import WinDLL      as DLL
from ctypes  import CFUNCTYPE   as CFUNC
from _ctypes import FreeLibrary as dlclose

# Taken from the file winsock.h.
#
# struct timeval {
#     long tv_sec;   /* seconds */
#     long tv_usec;  /* and microseconds */
# };

class timeval(ct.Structure):
    _fields_ = [
    ("tv_sec",  ct.c_long),  # seconds
    ("tv_usec", ct.c_long),  # microseconds
]

class sockaddr(ct.Structure): 
    _fields_ = [
    ("sa_family", ct.c_short), 
    ("__pad1",    ct.c_ushort), 
    ("ipv4_addr", ct.c_byte * 4), 
    ("ipv6_addr", ct.c_byte * 16), 
    ("__pad2",    ct.c_ulong),
] 

# IPv4 AF_INET sockets:

"""
typedef struct in_addr {
  union
  {
    struct
    {
      u_char s_b1,s_b2,s_b3,s_b4;
    } S_un_b;

    struct
    {
      u_short s_w1,s_w2;
    } S_un_w;

    u_long S_addr;
  } S_un;
};
"""

class in_addr(ct.Union):
    _fields_ = [
    ("s_addr", ct.c_uint32),  # ct.c_ulong
]

class sockaddr_in(ct.Structure):
    _fields_ = [
    ("sin_family", ct.c_short),       # e.g. AF_INET, AF_INET6   
    ("sin_port",   ct.c_ushort),      # e.g. htons(3490)         
    ("sin_addr",   in_addr),          # see struct in_addr, below
    ("sin_zero",   (ct.c_char * 8)),  # padding, zero this if you want to
]

# IPv6 AF_INET6 sockets:

class in6_addr(ct.Union):
    _fields_ = [
    ("s6_addr",   (ct.c_ubyte * 16)),
]

class sockaddr_in6(ct.Structure):
    _fields_ = [
    ('sin6_family',   ct.c_short),   # address family, AF_INET6      
    ('sin6_port',     ct.c_ushort),  # port number, Network Byte Order
    ('sin6_flowinfo', ct.c_ulong),   # IPv6 flow information         
    ('sin6_addr',     in6_addr),     # IPv6 address                  
    ('sin6_scope_id', ct.c_ulong),   # Scope ID                      
]
