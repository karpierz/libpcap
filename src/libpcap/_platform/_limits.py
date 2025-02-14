# Copyright (c) 1994 Adam Karpierz
# SPDX-License-Identifier: Zlib

import ctypes as ct

# include <limits.h>
USHRT_MAX  = ct.c_ushort(-1).value
SHRT_MAX   = USHRT_MAX >> 1
SHRT_MIN   = -SHRT_MAX - 1
UINT_MAX   = ct.c_uint(-1).value
INT_MAX    = UINT_MAX >> 1
INT_MIN    = -INT_MAX - 1
ULONG_MAX  = ct.c_ulong(-1).value
LONG_MAX   = ULONG_MAX >> 1
LONG_MIN   = -LONG_MAX - 1
ULLONG_MAX = ct.c_ulonglong(-1).value
LLONG_MAX  = ULLONG_MAX >> 1
LLONG_MIN  = -LLONG_MAX - 1

del ct
