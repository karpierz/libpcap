# Copyright (c) 2016 Adam Karpierz
# SPDX-License-Identifier: BSD-3-Clause

import ctypes as ct

from libpcap import is_windows

if is_windows:
    libc = ct.cdll.msvcrt
else:
    libc = ct.CDLL("libc.so.6")

ebuf2str = lambda ebuf: ebuf.value.decode("utf-8", "ignore")

def sock_initfuzz(data: ct.POINTER(ct.c_uint8), size: ct.c_size_t):
    # from ./sockutils.c - dummy for python
    pass
