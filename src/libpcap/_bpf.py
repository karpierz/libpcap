# flake8-in-file-ignores: noqa: E722

# Copyright (c) 2016 Adam Karpierz
# SPDX-License-Identifier: BSD-3-Clause

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
# 3. Neither the name of the University nor the names of its contributors
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
# At least two programs found by Google Code Search explicitly includes
# <pcap/bpf.h> (even though <pcap.h>/<pcap/pcap.h> includes it for you),
# so moving that stuff to <pcap/pcap.h> would break the build for some
# programs.

import ctypes as ct

from ._platform import defined
from ._platform import CFUNC
from ._dll      import dll

# Link-layer type codes.
#
from ._dlt import *  # noqa

PCAP_DEPRECATED = lambda func, msg: None

# BSD style release date

BPF_RELEASE = 199606

bpf_int32   = ct.c_int32   # int
bpf_u_int32 = ct.c_uint32  # u_int

# Alignment macros.  BPF_WORDALIGN rounds up to the next
# even multiple of BPF_ALIGNMENT.
#
# Tcpdump's print-pflog.c uses this, so we define it here.

if defined("__NetBSD__"):
    BPF_ALIGNMENT = ct.sizeof(ct.c_long)
else:
    BPF_ALIGNMENT = ct.sizeof(bpf_int32)
BPF_WORDALIGN = lambda x: ((x + (BPF_ALIGNMENT - 1)) & ~(BPF_ALIGNMENT - 1))

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
#         0x18  # reserved; used by BSD/OS
BPF_MODE = lambda code: (code & 0xE0)
BPF_IMM = 0x00
BPF_ABS = 0x20
BPF_IND = 0x40
BPF_MEM = 0x60
BPF_LEN = 0x80
BPF_MSH = 0xA0
#         0xc0  # reserved; used by BSD/OS; also by OpenBSD for BPF_RND
#         0xe0  # reserved; used by BSD/OS

# alu/jmp fields
BPF_OP = lambda code: (code & 0xF0)
BPF_ADD  = 0x00
BPF_SUB  = 0x10
BPF_MUL  = 0x20
BPF_DIV  = 0x30
BPF_OR   = 0x40
BPF_AND  = 0x50
BPF_LSH  = 0x60
BPF_RSH  = 0x70
BPF_NEG  = 0x80
BPF_MOD  = 0x90  # avail. from v.1.8.1
BPF_XOR  = 0xa0  # avail. from v.1.8.1
#          0xb0  # reserved
#          0xc0  # reserved
#          0xd0  # reserved
#          0xe0  # reserved
#          0xf0  # reserved

BPF_JA   = 0x00
BPF_JEQ  = 0x10
BPF_JGT  = 0x20
BPF_JGE  = 0x30
BPF_JSET = 0x40
#          0x50  # reserved; used on BSD/OS
#          0x60  # reserved
#          0x70  # reserved
#          0x80  # reserved
#          0x90  # reserved
#          0xa0  # reserved
#          0xb0  # reserved
#          0xc0  # reserved
#          0xd0  # reserved
#          0xe0  # reserved
#          0xf0  # reserved
BPF_SRC  = lambda code: (code & 0x08)
BPF_K    = 0x00
BPF_X    = 0x08

# ret - BPF_K and BPF_X also apply
BPF_RVAL = lambda code: (code & 0x18)
BPF_A = 0x10
#       0x18  # reserved

# misc
BPF_MISCOP = lambda code: (code & 0xF8)
BPF_TAX  = 0x00
#          0x08  # reserved
#          0x10  # reserved
#          0x18  # reserved
BPF_COP  = 0x20  # NetBSD "coprocessor" extensions # avail. from v.1.8.1
#          0x28  # reserved
#          0x30  # reserved
#          0x38  # reserved
BPF_COPX = 0x40  # NetBSD "coprocessor" extensions, also used on BSD/OS # avail. from v.1.8.1
#          0x48  # reserved
#          0x50  # reserved
#          0x58  # reserved
#          0x60  # reserved
#          0x68  # reserved
#          0x70  # reserved
#          0x78  # reserved
BPF_TXA  = 0x80
#          0x88  # reserved
#          0x90  # reserved
#          0x98  # reserved
#          0xa0  # reserved
#          0xa8  # reserved
#          0xb0  # reserved
#          0xb8  # reserved
#          0xc0  # reserved; used on BSD/OS
#          0xc8  # reserved
#          0xd0  # reserved
#          0xd8  # reserved
#          0xe0  # reserved
#          0xe8  # reserved
#          0xf0  # reserved
#          0xf8  # reserved

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


# Macros for insn array initializers.
#
# In case somebody's included <linux/filter.h>, or something else that
# gives the kernel's definitions of BPF statements, get rid of its
# definitions, so we can supply ours instead.  If some kernel's
# definitions aren't *binary-compatible* with what BPF has had
# since it first sprung from the brows of Van Jacobson and Steve
# McCanne, that kernel should be fixed.

BPF_STMT = lambda code, k:         (ct.c_ushort(code), 0,  0,  k)
BPF_JUMP = lambda code, k, jt, jf: (ct.c_ushort(code), jt, jf, k)

#
# Exported functions
#

try:  # PCAP_AVAILABLE_0_4
    bpf_filter = CFUNC(ct.c_uint,
        ct.POINTER(bpf_insn),
        ct.POINTER(ct.c_ubyte),
        ct.c_uint,
        ct.c_uint)(
        ("bpf_filter", dll), (
        (1, "insn"),
        (1, "buffer"),
        (1, "wirelen"),
        (1, "buflen"),))
    PCAP_DEPRECATED(bpf_filter,
                    "use pcap_offline_filter()")
except: pass

try:  # PCAP_AVAILABLE_0_6
    bpf_validate = CFUNC(ct.c_int,
        ct.POINTER(bpf_insn),
        ct.c_int)(
        ("bpf_validate", dll), (
        (1, "insn"),
        (1, "len"),))
except: pass

try:  # PCAP_AVAILABLE_0_4
    bpf_image = CFUNC(ct.c_char_p,
        ct.POINTER(bpf_insn),
        ct.c_int)(
        ("bpf_image", dll), (
        (1, "insn"),
        (1, "len"),))
except: pass

try:  # PCAP_AVAILABLE_0_6
    bpf_dump = CFUNC(None,
        ct.POINTER(bpf_program),
        ct.c_int)(
        ("bpf_dump", dll), (
        (1, "prog"),
        (1, "option"),))
except: pass

#
# Number of scratch memory words (for BPF_LD|BPF_MEM and BPF_ST).
#

BPF_MEMWORDS = 16

# eof
