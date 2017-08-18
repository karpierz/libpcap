# coding: utf-8

import sys
import os

this_dir = os.path.dirname(os.path.abspath(__file__))
is_py32bit = sys.maxsize <= 2**32

DLL_PATH = "C:/Windows/System32/wpcap.dll"

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

# eof
