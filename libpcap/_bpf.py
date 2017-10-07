# Copyright (c) 2016-2017, Adam Karpierz
# Licensed under the BSD license
# https://opensource.org/licenses/BSD-3-Clause

# Copyright (c) 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997
#    The Regents of the University of California.  All rights reserved.
#
# This code is derived from the Stanford/CMU enet packet filter,
# (net/enet.c) distributed as part of 4.3BSD, and code contributed
# to Berkeley by Steven McCanne and Van Jacobson both of Lawrence
# Berkeley Laboratory.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. All advertising materials mentioning features or use of this software
#    must display the following acknowledgement:
#      This product includes software developed by the University of
#      California, Berkeley and its contributors.
# 4. Neither the name of the University nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
#      @(#)bpf.h       7.1 (Berkeley) 5/7/91

# This is libpcap's cut-down version of bpf.h; it includes only
# the stuff needed for the code generator and the userland BPF
# interpreter, and the libpcap APIs for setting filters, etc..
#
# "pcap-bpf.c" will include the native OS version, as it deals with
# the OS's BPF implementation.
#
# XXX - should this all just be moved to "pcap.h"?

from __future__ import absolute_import

import ctypes as ct

from ._platform import defined
from ._platform import CFUNC
from ._dll      import dll

# BSD style release date

BPF_RELEASE = 199606

bpf_int32   = ct.c_int32   # int
bpf_u_int32 = ct.c_uint32  # u_int

# Alignment macros.  BPF_WORDALIGN rounds up to the next
# even multiple of BPF_ALIGNMENT.

if defined("__NetBSD__"):
    BPF_ALIGNMENT = ct.sizeof(ct.c_long)
else:
    BPF_ALIGNMENT = ct.sizeof(bpf_int32)
BPF_WORDALIGN = lambda x: ((x + (BPF_ALIGNMENT - 1)) & ~(BPF_ALIGNMENT - 1))

BPF_MAXBUFSIZE = 0x8000
BPF_MINBUFSIZE = 32

# Struct return by BIOCVERSION.  This represents the version number of
# the filter language described by the instruction encodings below.
# bpf understands a program iff kernel_major == filter_major &&
# kernel_minor >= filter_minor, that is, if the value returned by the
# running kernel has the same major number and a minor number equal
# equal to or less than the filter being downloaded.  Otherwise, the
# results are undefined, meaning an error may be returned or packets
# may be accepted haphazardly.
# It has nothing to do with the source code version.

class bpf_version(ct.Structure):
    _fields_ = [
    ("bv_major", ct.c_ushort),
    ("bv_minor", ct.c_ushort),
]

# Current version number of filter architecture.
BPF_MAJOR_VERSION = 1
BPF_MINOR_VERSION = 1

from ._dlt import *

#
# The instruction encodings.
#
# Please inform tcpdump-workers@lists.tcpdump.org if you use any
# of the reserved values, so that we can note that they're used
# (and perhaps implement it in the reference BPF implementation
# and encourage its implementation elsewhere).

# The upper 8 bits of the opcode aren't used. BSD/OS used 0x8000.

# instruction classes
BPF_CLASS = lambda code: (code & 0x07)
BPF_LD   = 0x00
BPF_LDX  = 0x01
BPF_ST   = 0x02
BPF_STX  = 0x03
BPF_ALU  = 0x04
BPF_JMP  = 0x05
BPF_RET  = 0x06
BPF_MISC = 0x07

# ld/ldx fields
BPF_SIZE = lambda code: (code & 0x18)
BPF_W   = 0x00
BPF_H   = 0x08
BPF_B   = 0x10
BPF_MODE = lambda code: (code & 0xE0)
BPF_IMM = 0x00
BPF_ABS = 0x20
BPF_IND = 0x40
BPF_MEM = 0x60
BPF_LEN = 0x80
BPF_MSH = 0xA0

# alu/jmp fields
BPF_OP = lambda code: (code & 0xF0)
BPF_ADD = 0x00
BPF_SUB = 0x10
BPF_MUL = 0x20
BPF_DIV = 0x30
BPF_OR  = 0x40
BPF_AND = 0x50
BPF_LSH = 0x60
BPF_RSH = 0x70
BPF_NEG = 0x80
BPF_JA  = 0x00
BPF_JEQ = 0x10
BPF_JGT = 0x20
BPF_JGE = 0x30
BPF_JSET= 0x40
BPF_SRC = lambda code: (code & 0x08)
BPF_K   = 0x00
BPF_X   = 0x08

# ret - BPF_K and BPF_X also apply
BPF_RVAL = lambda code: (code & 0x18)
BPF_A = 0x10

# misc
BPF_MISCOP = lambda code: (code & 0xF8)
BPF_TAX = 0x00
BPF_TXA = 0x80

#
# The instruction data structure.
#

class bpf_insn(ct.Structure):
    _fields_ = [
    ("code", ct.c_ushort),
    ("jt",   ct.c_ubyte),
    ("jf",   ct.c_ubyte),
    ("k",    bpf_u_int32),
]

#
# Structure for "pcap.compile()", "pcap.setfilter()", etc..
#

class bpf_program(ct.Structure):
    _fields_ = [
    ("bf_len",   ct.c_uint),
    ("bf_insns", ct.POINTER(bpf_insn)),
]

#
# Macros for insn array initializers.
#

BPF_STMT = lambda code, k:         (ct.c_ushort(code), 0,  0,  k)
BPF_JUMP = lambda code, k, jt, jf: (ct.c_ushort(code), jt, jf, k)

#
# Exported functions
#

bpf_filter   = CFUNC(ct.c_uint,
                     ct.POINTER(bpf_insn),
                     ct.POINTER(ct.c_ubyte),
                     ct.c_uint,
                     ct.c_uint)(
                     ("bpf_filter", dll), (
                     (1, "insn"),
                     (1, "buffer"),
                     (1, "wirelen"),
                     (1, "buflen"),))

bpf_validate = CFUNC(ct.c_int,
                     ct.POINTER(bpf_insn),
                     ct.c_int)(
                     ("bpf_validate", dll), (
                     (1, "insn"),
                     (1, "len"),))

bpf_image    = CFUNC(ct.c_char_p,
                     ct.POINTER(bpf_insn),
                     ct.c_int)(
                     ("bpf_image", dll), (
                     (1, "insn"),
                     (1, "len"),))

bpf_dump     = CFUNC(None,
                     ct.POINTER(bpf_program),
                     ct.c_int)(
                     ("bpf_dump", dll), (
                     (1, "prog"),
                     (1, "option"),))

#
# Number of scratch memory words (for BPF_LD|BPF_MEM and BPF_ST).
#

BPF_MEMWORDS = 16

# eof
