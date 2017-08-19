# coding: utf-8

# Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
# Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
# 3. Neither the name of the Politecnico di Torino, CACE Technologies
# nor the names of its contributors may be used to endorse or promote
# products derived from this software without specific prior written
# permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# file: _win32_ext
#
# Includes the wpcap-specific extensions

from __future__ import absolute_import

import ctypes as ct
import ctypes.wintypes

from ._platform import CFUNC
from ._dll      import dll
from ._pcap     import pcap_t, pkthdr, stat, bpf_program

# Definitions

#
# A queue of raw packets that will be sent to the network with
# pcap.sendqueue_transmit().
#

class send_queue(ct.Structure):
    _fields_ = [
    ("maxlen", ct.c_uint),    # Maximum size of the queue, in bytes. This
                              # variable contains the size of the buffer field.
    ("len",    ct.c_uint),    # Current size of the queue, in bytes.
    ("buffer", ct.c_char_p),  # Buffer containing the packets to be sent.
]

#
# This typedef is a support for the pcap.get_airpcap_handle() function
#

class _AirpcapHandle(ct.Structure): pass
PAirpcapHandle = ct.POINTER(_AirpcapHandle)

BPF_MEM_EX_IMM = 0xC0
BPF_MEM_EX_IND = 0xE0

# used for ST
BPF_MEM_EX = 0xC0
BPF_TME    = 0x08

BPF_LOOKUP             = 0x90
BPF_EXECUTE            = 0xA0
BPF_INIT               = 0xB0
BPF_VALIDATE           = 0xC0
BPF_SET_ACTIVE         = 0xD0
BPF_RESET              = 0xE0
BPF_SET_MEMORY         = 0x80
BPF_GET_REGISTER_VALUE = 0x70
BPF_SET_REGISTER_VALUE = 0x60
BPF_SET_WORKING        = 0x50
BPF_SET_ACTIVE_READ    = 0x40
BPF_SET_AUTODELETION   = 0x30
BPF_SEPARATION         = 0xFF

#
# Exported functions
#

sendqueue_alloc    = CFUNC(ct.POINTER(send_queue),
                           ct.c_uint)(
                           ("pcap_sendqueue_alloc", dll), (
                           (1, "memsize"),))

sendqueue_destroy  = CFUNC(None,
                           ct.POINTER(send_queue))(
                           ("pcap_sendqueue_destroy", dll), (
                           (1, "queue"),))

sendqueue_queue    = CFUNC(ct.c_int,
                           ct.POINTER(send_queue),
                           ct.POINTER(pkthdr),
                           ct.POINTER(ct.c_ubyte))(
                           ("pcap_sendqueue_queue", dll), (
                           (1, "queue"),
                           (1, "pkt_header"),
                           (1, "pkt_data"),))

sendqueue_transmit = CFUNC(ct.c_uint,
                           ct.POINTER(pcap_t),
                           ct.POINTER(send_queue),
                           ct.c_int)(
                           ("pcap_sendqueue_transmit", dll), (
                           (1, "pcap"),
                           (1, "queue"),
                           (1, "sync"),))

getevent           = CFUNC(ct.wintypes.HANDLE,
                           ct.POINTER(pcap_t))(
                           ("pcap_getevent", dll), (
                           (1, "pcap"),))

stats_ex           = CFUNC(ct.POINTER(stat),
                           ct.POINTER(pcap_t),
                           ct.POINTER(ct.c_int))(
                           ("pcap_stats_ex", dll), (
                           (1, "pcap"),
                           (1, "stat_size"),))

setuserbuffer      = CFUNC(ct.c_int,
                           ct.POINTER(pcap_t),
                           ct.c_int)(
                           ("pcap_setuserbuffer", dll), (
                           (1, "pcap"),
                           (1, "size"),))

live_dump           = CFUNC(ct.c_int,
                           ct.POINTER(pcap_t),
                           ct.c_char_p,
                           ct.c_int,
                           ct.c_int)(
                           ("pcap_live_dump", dll), (
                           (1, "pcap"),
                           (1, "filename"),
                           (1, "maxsize"),
                           (1, "maxpacks"),))

live_dump_ended    = CFUNC(ct.c_int,
                           ct.POINTER(pcap_t),
                           ct.c_int)(
                           ("pcap_live_dump_ended", dll), (
                           (1, "pcap"),
                           (1, "sync"),))

offline_filter     = CFUNC(ct.c_int,
                           ct.POINTER(bpf_program),
                           ct.POINTER(pkthdr),
                           ct.POINTER(ct.c_ubyte))(
                           ("pcap_offline_filter", dll), (
                           (1, "prog"),
                           (1, "pkt_header"),
                           (1, "pkt_data"),))

try:
    start_oem      = CFUNC(ct.c_int,
                           ct.c_char_p,
                           ct.c_int)(
                           ("pcap_start_oem", dll), (
                           (1, "err_str"),
                           (1, "flags"),))
except: pass

get_airpcap_handle = CFUNC(PAirpcapHandle,
                           ct.POINTER(pcap_t))(
                           ("pcap_get_airpcap_handle", dll), (
                           (1, "pcap"),))

# eof
