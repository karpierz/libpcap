# Copyright (c) 2016-2017, Adam Karpierz
# Licensed under the BSD license
# https://opensource.org/licenses/BSD-3-Clause

# Copyright (c) 1993, 1994, 1995, 1996, 1997
#    The Regents of the University of California.  All rights reserved.
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
#    This product includes software developed by the Computer Systems
#    Engineering Group at Lawrence Berkeley Laboratory.
# 4. Neither the name of the University nor of the Laboratory may be used
#    to endorse or promote products derived from this software without
#    specific prior written permission.
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

from __future__ import absolute_import

import os
import ctypes as ct
intptr_t = (ct.c_int32 if ct.sizeof(ct.c_void_p) == ct.sizeof(ct.c_int32)
            else ct.c_int64)

from ._platform import is_windows, defined
from ._platform import CFUNC
from ._platform import timeval, sockaddr
from ._dll      import dll

try:
    ct.c_void_p.in_dll(dll, "pcap_remoteact_accept")
    HAVE_REMOTE = True
except ValueError:
    pass

from ._bpf import *


class FILE(ct.Structure): pass

# Version number of the current version of the pcap file format.
#
# NOTE: this is *NOT* the version number of the libpcap library.
# To fetch the version information for the version of libpcap
# you're using, use pcap_lib_version().

PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4

PCAP_ERRBUF_SIZE = 256

# Compatibility for systems that have a bpf.h that
# predates the bpf typedefs for 64-bit support.

if BPF_RELEASE - 0 < 199406:
    bpf_int32   = ct.c_int
    bpf_u_int32 = ct.c_uint

class pcap(ct.Structure): pass
pcap_t = pcap
class pcap_dumper(ct.Structure): pass
pcap_dumper_t = pcap_dumper

# The first record in the file contains saved values for some
# of the flags used in the printout phases of tcpdump.
# Many fields here are 32 bit ints so compilers won't insert unwanted
# padding; these files need to be interchangeable across architectures.
#
# Do not change the layout of this structure, in any way (this includes
# changes that only affect the length of fields in this structure).
#
# Also, do not change the interpretation of any of the members of this
# structure, in any way (this includes using values other than
# LINKTYPE_ values, as defined in "savefile.c", in the "linktype"
# field).
#
# Instead:
#
#    introduce a new structure for the new format, if the layout
#    of the structure changed;
#
#    send mail to "tcpdump-workers@lists.tcpdump.org", requesting
#    a new magic number for your new capture file format, and, when
#    you get the new magic number, put it in "savefile.c";
#
#    use that magic number for save files with the changed file
#    header;
#
#    make the code in "savefile.c" capable of reading files with
#    the old file header as well as files with the new file header
#    (using the magic number to determine the header format).
#
# Then supply the changes by forking the branch at
#
#    https://github.com/the-tcpdump-group/libpcap/issues
#
# and issuing a pull request, so that future versions of libpcap and
# programs that use it (such as tcpdump) will be able to read your new
# capture file format.

class file_header(ct.Structure):
    _fields_ = [
    ("magic",         bpf_u_int32),
    ("version_major", ct.c_ushort),
    ("version_minor", ct.c_ushort),
    ("thiszone",      bpf_int32),    # gmt to local correction
    ("sigfigs",       bpf_u_int32),  # accuracy of timestamps
    ("snaplen",       bpf_u_int32),  # max length saved portion of each pkt
    ("linktype",      bpf_u_int32),  # data link type (LINKTYPE_*)
]

# Macros for the value returned by pcap.datalink_ext().
#
# If LT_FCS_LENGTH_PRESENT(x) is true, the LT_FCS_LENGTH(x) macro
# gives the FCS length of packets in the capture.

LT_FCS_LENGTH_PRESENT = lambda x: (x & 0x04000000)
LT_FCS_LENGTH         = lambda x: ((x & 0xF0000000) >> 28)
LT_FCS_DATALINK_EXT   = lambda x: (((x & 0xF) << 28) | 0x04000000)

direction_t = ct.c_int
(
    PCAP_D_INOUT,
    PCAP_D_IN,
    PCAP_D_OUT

) = (0, 1, 2)

# Generic per-packet information, as supplied by libpcap.
#
# The time stamp can and should be a "struct timeval", regardless of
# whether your system supports 32-bit tv_sec in "struct timeval",
# 64-bit tv_sec in "struct timeval", or both if it supports both 32-bit
# and 64-bit applications.  The on-disk format of savefiles uses 32-bit
# tv_sec (and tv_usec); this structure is irrelevant to that.  32-bit
# and 64-bit versions of libpcap, even if they're on the same platform,
# should supply the appropriate version of "struct timeval", even if
# that's not what the underlying packet capture mechanism supplies.

class pkthdr(ct.Structure):
    _fields_ = [
    ("ts",     timeval),      # time stamp
    ("caplen", bpf_u_int32),  # length of portion present
    ("len",    bpf_u_int32),  # length this packet (off wire)
]

#
# As returned by the pcap.stats()
#

class stat(ct.Structure): pass
_fields_ = [
    ("ps_recv",    ct.c_uint),  # number of packets received
    ("ps_drop",    ct.c_uint),  # number of packets dropped
    ("ps_ifdrop",  ct.c_uint),  # drops by interface -- only supported on some platforms
]
if is_windows and defined("HAVE_REMOTE"):
    _fields_ += [
        ("ps_capt",    ct.c_uint),  # number of packets that are received by the application;
                                    # please get rid off the Win32 ifdef
        ("ps_sent",    ct.c_uint),  # number of packets sent by the server on the network
        ("ps_netdrop", ct.c_uint),  # number of packets lost on the network
    ]
stat._fields_ = _fields_

if defined("MSDOS"):

    #
    # As returned by the pcap.stats_ex()
    #

    class stat_ex(ct.Structure):
        _fields_ = [
           ("rx_packets",          ct.c_ulong),  # total packets received
           ("tx_packets",          ct.c_ulong),  # total packets transmitted
           ("rx_bytes",            ct.c_ulong),  # total bytes received
           ("tx_bytes",            ct.c_ulong),  # total bytes transmitted
           ("rx_errors",           ct.c_ulong),  # bad packets received
           ("tx_errors",           ct.c_ulong),  # packet transmit problems
           ("rx_dropped",          ct.c_ulong),  # no space in Rx buffers
           ("tx_dropped",          ct.c_ulong),  # no space available for Tx
           ("multicast",           ct.c_ulong),  # multicast packets received
           ("collisions",          ct.c_ulong),
           # detailed rx_errors:
           ("rx_length_errors",    ct.c_ulong),
           ("rx_over_errors",      ct.c_ulong),  # receiver ring buff overflow
           ("rx_crc_errors",       ct.c_ulong),  # recv'd pkt with crc error
           ("rx_frame_errors",     ct.c_ulong),  # recv'd frame alignment error
           ("rx_fifo_errors",      ct.c_ulong),  # recv'r fifo overrun
           ("rx_missed_errors",    ct.c_ulong),  # recv'r missed packet
           # detailed tx_errors
           ("tx_aborted_errors",   ct.c_ulong),
           ("tx_carrier_errors",   ct.c_ulong),
           ("tx_fifo_errors",      ct.c_ulong),
           ("tx_heartbeat_errors", ct.c_ulong),
           ("tx_window_errors",    ct.c_ulong),
     ]

#endif # MSDOS

#
# Representation of an interface address.
#

class pcap_addr(ct.Structure): pass
pcap_addr._fields_ = [
    ("next",      ct.POINTER(pcap_addr)),
    ("addr",      ct.POINTER(sockaddr)),  # address
    ("netmask",   ct.POINTER(sockaddr)),  # netmask for that address
    ("broadaddr", ct.POINTER(sockaddr)),  # broadcast address for that address
    ("dstaddr",   ct.POINTER(sockaddr)),  # P2P destination address for that address
]
pcap_addr_t = pcap_addr

#
# Item in a list of interfaces.
#

class pcap_if(ct.Structure): pass
pcap_if._fields_ = [
    ("next",        ct.POINTER(pcap_if)),
    ("name",        ct.c_char_p),  # name to hand to "pcap.open_live()"
    ("description", ct.c_char_p),  # textual description of interface, or NULL
    ("addresses",   ct.POINTER(pcap_addr)),
    ("flags",       bpf_u_int32),  # PCAP_IF_ interface flags
]
pcap_if_t = pcap_if

PCAP_IF_LOOPBACK = 0x00000001  # interface is loopback
PCAP_IF_UP       = 0x00000002  # interface is up
PCAP_IF_RUNNING  = 0x00000004  # interface is running

pcap_handler = CFUNC(None, ct.POINTER(ct.c_ubyte), ct.POINTER(pkthdr), ct.POINTER(ct.c_ubyte))

# Error codes for the pcap API.
# These will all be negative, so you can check for the success or
# failure of a call that returns these codes by checking for a
# negative value.

PCAP_ERROR                         = -1   # generic error code
PCAP_ERROR_BREAK                   = -2   # loop terminated by pcap.breakloop
PCAP_ERROR_NOT_ACTIVATED           = -3   # the capture needs to be activated
PCAP_ERROR_ACTIVATED               = -4   # the operation can't be performed on already activated captures
PCAP_ERROR_NO_SUCH_DEVICE          = -5   # no such device exists
PCAP_ERROR_RFMON_NOTSUP            = -6   # this device doesn't support rfmon (monitor) mode
PCAP_ERROR_NOT_RFMON               = -7   # operation supported only in monitor mode
PCAP_ERROR_PERM_DENIED             = -8   # no permission to open the device
PCAP_ERROR_IFACE_NOT_UP            = -9   # interface isn't up
PCAP_ERROR_CANTSET_TSTAMP_TYPE     = -10  # this device doesn't support setting the time stamp type
PCAP_ERROR_PROMISC_PERM_DENIED     = -11  # you don't have permission to capture in promiscuous mode
PCAP_ERROR_TSTAMP_PRECISION_NOTSUP = -12  # the requested time stamp precision is not supported

# Warning codes for the pcap API.
# These will all be positive and non-zero, so they won't look like
# errors.

PCAP_WARNING                    = 1  # generic warning code
PCAP_WARNING_PROMISC_NOTSUP     = 2  # this device doesn't support promiscuous mode
PCAP_WARNING_TSTAMP_TYPE_NOTSUP = 3  # the requested time stamp type is not supported

# Value to pass to pcap_compile() as the netmask if you don't know what
# the netmask is.

PCAP_NETMASK_UNKNOWN = 0xFFFFFFFF

# Time stamp types.
# Not all systems and interfaces will necessarily support all of these.
#
# A system that supports PCAP_TSTAMP_HOST is offering time stamps
# provided by the host machine, rather than by the capture device,
# but not committing to any characteristics of the time stamp;
# it will not offer any of the PCAP_TSTAMP_HOST_ subtypes.
#
# PCAP_TSTAMP_HOST_LOWPREC is a time stamp, provided by the host machine,
# that's low-precision but relatively cheap to fetch; it's normally done
# using the system clock, so it's normally synchronized with times you'd
# fetch from system calls.
#
# PCAP_TSTAMP_HOST_HIPREC is a time stamp, provided by the host machine,
# that's high-precision; it might be more expensive to fetch.  It might
# or might not be synchronized with the system clock, and might have
# problems with time stamps for packets received on different CPUs,
# depending on the platform.
#
# PCAP_TSTAMP_ADAPTER is a high-precision time stamp supplied by the
# capture device; it's synchronized with the system clock.
#
# PCAP_TSTAMP_ADAPTER_UNSYNCED is a high-precision time stamp supplied by
# the capture device; it's not synchronized with the system clock.
#
# Note that time stamps synchronized with the system clock can go
# backwards, as the system clock can go backwards.  If a clock is
# not in sync with the system clock, that could be because the
# system clock isn't keeping accurate time, because the other
# clock isn't keeping accurate time, or both.
#
# Note that host-provided time stamps generally correspond to the
# time when the time-stamping code sees the packet; this could
# be some unknown amount of time after the first or last bit of
# the packet is received by the network adapter, due to batching
# of interrupts for packet arrival, queueing delays, etc..

PCAP_TSTAMP_HOST             = 0  # host-provided, unknown characteristics
PCAP_TSTAMP_HOST_LOWPREC     = 1  # host-provided, low precision
PCAP_TSTAMP_HOST_HIPREC      = 2  # host-provided, high precision
PCAP_TSTAMP_ADAPTER          = 3  # device-provided, synced with the system clock
PCAP_TSTAMP_ADAPTER_UNSYNCED = 4  # device-provided, not synced with the system clock

# Time stamp resolution types.
# Not all systems and interfaces will necessarily support all of these
# resolutions when doing live captures; all of them can be requested
# when reading a savefile.

PCAP_TSTAMP_PRECISION_MICRO = 0  # use timestamps with microsecond precision, default
PCAP_TSTAMP_PRECISION_NANO  = 1  # use timestamps with nanosecond precision

#
# Exported functions
#

lookupdev     = CFUNC(ct.c_char_p,
                      ct.c_char_p)(
                      ("pcap_lookupdev", dll), (
                      (1, "errbuf"),))

lookupnet     = CFUNC(ct.c_int,
                      ct.c_char_p,
                      ct.POINTER(bpf_u_int32),
                      ct.POINTER(bpf_u_int32),
                      ct.c_char_p)(
                      ("pcap_lookupnet", dll), (
                      (1, "device"),
                      (1, "netp"),
                      (1, "maskp"),
                      (1, "errbuf"),))

create        = CFUNC(ct.POINTER(pcap_t),
                      ct.c_char_p,
                      ct.c_char_p)(
                      ("pcap_create", dll), (
                      (1, "source"),
                      (1, "errbuf"),))

set_snaplen   = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t),
                      ct.c_int)(
                      ("pcap_set_snaplen", dll), (
                      (1, "pcap"),
                      (1, "snaplen"),))

set_promisc   = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t),
                      ct.c_int)(
                      ("pcap_set_promisc", dll), (
                      (1, "pcap"),
                      (1, "promisc"),))

try:
    can_set_rfmon = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t))(
                      ("pcap_can_set_rfmon", dll), (
                      (1, "pcap"),))
except: pass

try:
    set_rfmon = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t),
                      ct.c_int)(
                      ("pcap_set_rfmon", dll), (
                      (1, "pcap"),
                      (1, "rfmon"),))
except: pass

set_timeout   = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t),
                      ct.c_int)(
                      ("pcap_set_timeout", dll), (
                      (1, "pcap"),
                      (1, "timeout"),))

try:
    set_tstamp_type = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t),
                      ct.c_int)(
                      ("pcap_set_tstamp_type", dll), (
                      (1, "pcap"),
                      (1, "tstamp_type"),))
except: pass

try:
    set_immediate_mode = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t),
                      ct.c_int)(
                      ("pcap_set_immediate_mode", dll), (
                      (1, "pcap"),
                      (1, "immediate"),))
except: pass

set_buffer_size = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t),
                      ct.c_int)(
                      ("pcap_set_buffer_size", dll), (
                      (1, "pcap"),
                      (1, "buffer_size"),))

try:
    set_tstamp_precision = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t),
                      ct.c_int)(
                      ("pcap_set_tstamp_precision", dll), (
                      (1, "pcap"),
                      (1, "tstamp_precision"),))
except: pass

try:
    get_tstamp_precision = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t))(
                      ("pcap_get_tstamp_precision", dll), (
                      (1, "pcap"),))
except: pass

try:
    list_tstamp_types = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t),
                      ct.POINTER(ct.POINTER(ct.c_int)))(
                      ("pcap_list_tstamp_types", dll), (
                      (1, "pcap"),
                      (1, "tstamp_type_list"),))
except: pass

try:
    free_tstamp_types = CFUNC(None,
                      ct.POINTER(ct.c_int))(
                      ("pcap_free_tstamp_types", dll), (
                      (1, "tstamp_type_list"),))
except: pass

try:
    tstamp_type_name_to_val = CFUNC(ct.c_int,
                      ct.c_char_p)(
                      ("pcap_tstamp_type_name_to_val", dll), (
                      (1, "name"),))
except: pass

try:
    tstamp_type_val_to_name = CFUNC(ct.c_char_p,
                      ct.c_int)(
                      ("pcap_tstamp_type_val_to_name", dll), (
                      (1, "tstamp_type"),))
except: pass

try:
    tstamp_type_val_to_description = CFUNC(ct.c_char_p,
                      ct.c_int)(
                      ("pcap_tstamp_type_val_to_description", dll), (
                      (1, "tstamp_type"),))
except: pass

activate      = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t))(
                      ("pcap_activate", dll), (
                      (1, "pcap"),))

open_live     = CFUNC(ct.POINTER(pcap_t),
                      ct.c_char_p,
                      ct.c_int,
                      ct.c_int,
                      ct.c_int,
                      ct.c_char_p)(
                      ("pcap_open_live", dll), (
                      (1, "source"),
                      (1, "snaplen"),
                      (1, "promisc"),
                      (1, "timeout"),
                      (1, "errbuf"),))

open_dead     = CFUNC(ct.POINTER(pcap_t),
                      ct.c_int,
                      ct.c_int)(
                      ("pcap_open_dead", dll), (
                      (1, "linktype"),
                      (1, "snaplen"),))

try:
    open_dead_with_tstamp_precision = CFUNC(ct.POINTER(pcap_t),
                      ct.c_int,
                      ct.c_int,
                      ct.c_uint)(
                      ("pcap_open_dead_with_tstamp_precision", dll), (
                      (1, "linktype"),
                      (1, "snaplen"),
                      (1, "precision"),))
except: pass

open_offline  = CFUNC(ct.POINTER(pcap_t),
                      ct.c_char_p,
                      ct.c_char_p)(
                      ("pcap_open_offline", dll), (
                      (1, "fname"),
                      (1, "errbuf"),))

try:
    open_offline_with_tstamp_precision = CFUNC(ct.POINTER(pcap_t),
                      ct.c_char_p,
                      ct.c_uint,
                      ct.c_char_p)(
                      ("pcap_open_offline_with_tstamp_precision", dll), (
                      (1, "fname"),
                      (1, "precision"),
                      (1, "errbuf"),))
except: pass

if is_windows:
    hopen_offline = CFUNC(ct.POINTER(pcap_t),
                      intptr_t,
                      ct.c_char_p)(
                      ("pcap_hopen_offline", dll), (
                      (1, "osfd"),
                      (1, "errbuf"),))

    #@CFUNC(ct.POINTER(pcap_t), ct.POINTER(FILE), ct.c_char_p)
    def fopen_offline(fp, errbuf, libc=ct.cdll.msvcrt):
        return hopen_offline(libc._get_osfhandle(libc._fileno(fp)), errbuf)

    try:
        hopen_offline_with_tstamp_precision = CFUNC(ct.POINTER(pcap_t),
                          intptr_t,
                          ct.c_uint,
                          ct.c_char_p)(
                          ("pcap_hopen_offline_with_tstamp_precision", dll), (
                          (1, "osfd"),
                          (1, "precision"),
                          (1, "errbuf"),))

        #@CFUNC(ct.POINTER(pcap_t), ct.POINTER(FILE), ct.c_uint, ct.c_char_p)
        def fopen_offline_with_tstamp_precision(fp, precision, errbuf, libc=ct.cdll.msvcrt):
            return hopen_offline_with_tstamp_precision(libc._get_osfhandle(libc._fileno(fp)),
                                                       precision, errbuf)
    except: pass
else:
    fopen_offline = CFUNC(ct.POINTER(pcap_t),
                      ct.POINTER(FILE),
                      ct.c_char_p)(
                      ("pcap_fopen_offline", dll), (
                      (1, "fp"),
                      (1, "errbuf"),))

    try:
        fopen_offline_with_tstamp_precision = CFUNC(ct.POINTER(pcap_t),
                      ct.POINTER(FILE),
                      ct.c_uint,
                      ct.c_char_p)(
                      ("pcap_fopen_offline_with_tstamp_precision", dll), (
                      (1, "fp"),
                      (1, "precision"),
                      (1, "errbuf"),))
    except: pass

close         = CFUNC(None,
                      ct.POINTER(pcap_t))(
                      ("pcap_close", dll), (
                      (1, "pcap"),))

loop          = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t),
                      ct.c_int,
                      pcap_handler,
                      ct.POINTER(ct.c_ubyte))(
                      ("pcap_loop", dll), (
                      (1, "pcap"),
                      (1, "cnt"),
                      (1, "callback"),
                      (1, "user"),))

dispatch      = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t),
                      ct.c_int,
                      pcap_handler,
                      ct.POINTER(ct.c_ubyte))(
                      ("pcap_dispatch", dll), (
                      (1, "pcap"),
                      (1, "cnt"),
                      (1, "callback"),
                      (1, "user"),))

next          = CFUNC(ct.POINTER(ct.c_ubyte),
                      ct.POINTER(pcap_t),
                      ct.POINTER(pkthdr))(
                      ("pcap_next", dll), (
                      (1, "pcap"),
                      (1, "pkt_header"),))

next_ex       = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t),
                      ct.POINTER(ct.POINTER(pkthdr)),
                      ct.POINTER(ct.POINTER(ct.c_ubyte)))(
                      ("pcap_next_ex", dll), (
                      (1, "pcap"),
                      (1, "pkt_header"),
                      (1, "pkt_data"),))

breakloop     = CFUNC(None,
                      ct.POINTER(pcap_t))(
                      ("pcap_breakloop", dll), (
                      (1, "pcap"),))

stats         = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t),
                      ct.POINTER(stat))(
                      ("pcap_stats", dll), (
                      (1, "pcap"),
                      (1, "stat"),))

setfilter     = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t),
                      ct.POINTER(bpf_program))(
                      ("pcap_setfilter", dll), (
                      (1, "pcap"),
                      (1, "prog"),))

setdirection  = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t),
                      direction_t)(
                      ("pcap_setdirection", dll), (
                      (1, "pcap"),
                      (1, "direction"),))

getnonblock   = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t),
                      ct.c_char_p)(
                      ("pcap_getnonblock", dll), (
                      (1, "pcap"),
                      (1, "errbuf"),))

setnonblock   = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t),
                      ct.c_int,
                      ct.c_char_p)(
                      ("pcap_setnonblock", dll), (
                      (1, "pcap"),
                      (1, "nonblock"),
                      (1, "errbuf"),))

try:
    inject    = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t),
                      ct.c_void_p,
                      ct.c_size_t)(
                      ("pcap_inject", dll), (
                      (1, "pcap"),
                      (1, "buffer"),
                      (1, "size"),))
except: pass

sendpacket    = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t),
                      ct.POINTER(ct.c_ubyte),
                      ct.c_int)(
                      ("pcap_sendpacket", dll), (
                      (1, "pcap"),
                      (1, "buffer"),
                      (1, "size"),))

try:
    statustostr = CFUNC(ct.c_char_p,
                      ct.c_int)(
                      ("pcap_statustostr", dll), (
                      (1, "errnum"),))
except: pass

strerror      = CFUNC(ct.c_char_p,
                      ct.c_int)(
                      ("pcap_strerror", dll), (
                      (1, "errnum"),))

geterr        = CFUNC(ct.c_char_p,
                      ct.POINTER(pcap_t))(
                      ("pcap_geterr", dll), (
                      (1, "pcap"),))

perror        = CFUNC(None,
                      ct.POINTER(pcap_t),
                      ct.c_char_p)(
                      ("pcap_perror", dll), (
                      (1, "pcap"),
                      (1, "prefix"),))

compile       = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t),
                      ct.POINTER(bpf_program),
                      ct.c_char_p,
                      ct.c_int,
                      bpf_u_int32)(
                      ("pcap_compile", dll), (
                      (1, "pcap"),
                      (1, "prog"),
                      (1, "buffer"),
                      (1, "optimize"),
                      (1, "mask"),))

compile_nopcap = CFUNC(ct.c_int,
                      ct.c_int,
                      ct.c_int,
                      ct.POINTER(bpf_program),
                      ct.c_char_p,
                      ct.c_int,
                      bpf_u_int32)(
                      ("pcap_compile_nopcap", dll), (
                      (1, "snaplen_arg"),
                      (1, "linktype"),
                      (1, "prog"),
                      (1, "buffer"),
                      (1, "optimize"),
                      (1, "mask"),))

freecode      = CFUNC(None,
                      ct.POINTER(bpf_program))(
                      ("pcap_freecode", dll), (
                      (1, "prog"),))

offline_filter = CFUNC(ct.c_int,
                      ct.POINTER(bpf_program),
                      ct.POINTER(pkthdr),
                      ct.POINTER(ct.c_ubyte))(
                      ("pcap_offline_filter", dll), (
                      (1, "prog"),
                      (1, "pkt_header"),
                      (1, "pkt_data"),))

datalink      = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t))(
                      ("pcap_datalink", dll), (
                      (1, "pcap"),))

try:
    datalink_ext = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t))(
                      ("pcap_datalink_ext", dll), (
                      (1, "pcap"),))
except: pass

list_datalinks = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t),
                      ct.POINTER(ct.POINTER(ct.c_int)))(
                      ("pcap_list_datalinks", dll), (
                      (1, "pcap"),
                      (1, "dlt_buffer"),))

set_datalink  = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t),
                      ct.c_int)(
                      ("pcap_set_datalink", dll), (
                      (1, "pcap"),
                      (1, "dlt"),))

free_datalinks = CFUNC(None,
                      ct.POINTER(ct.c_int))(
                      ("pcap_free_datalinks", dll), (
                      (1, "dlt_list"),))

datalink_name_to_val = CFUNC(ct.c_int,
                      ct.c_char_p)(
                      ("pcap_datalink_name_to_val", dll), (
                      (1, "name"),))

datalink_val_to_name = CFUNC(ct.c_char_p,
                      ct.c_int)(
                      ("pcap_datalink_val_to_name", dll), (
                      (1, "dlt"),))

datalink_val_to_description = CFUNC(ct.c_char_p,
                      ct.c_int)(
                      ("pcap_datalink_val_to_description", dll), (
                      (1, "dlt"),))

snapshot      = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t))(
                      ("pcap_snapshot", dll), (
                      (1, "pcap"),))

is_swapped    = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t))(
                      ("pcap_is_swapped", dll), (
                      (1, "pcap"),))

major_version = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t))(
                      ("pcap_major_version", dll), (
                      (1, "pcap"),))

minor_version = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t))(
                      ("pcap_minor_version", dll), (
                      (1, "pcap"),))

# XXX
file          = CFUNC(ct.POINTER(FILE),
                      ct.POINTER(pcap_t))(
                      ("pcap_file", dll), (
                      (1, "pcap"),))

fileno        = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t))(
                      ("pcap_fileno", dll), (
                      (1, "pcap"),))

dump_open     = CFUNC(ct.POINTER(pcap_dumper_t),
                      ct.POINTER(pcap_t),
                      ct.c_char_p)(
                      ("pcap_dump_open", dll), (
                      (1, "pcap"),
                      (1, "fname"),))

try:
    dump_open_append = CFUNC(ct.POINTER(pcap_dumper_t),
                      ct.POINTER(pcap_t),
                      ct.c_char_p)(
                      ("pcap_dump_open_append", dll), (
                      (1, "pcap"),
                      (1, "fname"),))
except: pass

try:
    dump_fopen = CFUNC(ct.POINTER(pcap_dumper_t),
                      ct.POINTER(pcap_t),
                      ct.POINTER(FILE))(
                      ("pcap_dump_fopen", dll), (
                      (1, "pcap"),
                      (1, "fp"),))
except: pass

dump_file     = CFUNC(ct.POINTER(FILE),
                      ct.POINTER(pcap_dumper_t))(
                      ("pcap_dump_file", dll), (
                      (1, "pcap_dumper"),))

dump_ftell    = CFUNC(ct.c_long,
                      ct.POINTER(pcap_dumper_t))(
                      ("pcap_dump_ftell", dll), (
                      (1, "pcap_dumper"),))

dump_flush    = CFUNC(ct.c_int,
                      ct.POINTER(pcap_dumper_t))(
                      ("pcap_dump_flush", dll), (
                      (1, "pcap_dumper"),))

dump_close    = CFUNC(None,
                      ct.POINTER(pcap_dumper_t))(
                      ("pcap_dump_close", dll), (
                      (1, "pcap_dumper"),))

dump          = CFUNC(None,
                      ct.POINTER(ct.c_ubyte),
                      ct.POINTER(pkthdr),
                      ct.POINTER(ct.c_ubyte))(
                      ("pcap_dump", dll), (
                      (1, "fhandle"),
                      (1, "pkt_header"),
                      (1, "pkt_data"),))

findalldevs   = CFUNC(ct.c_int,
                      ct.POINTER(ct.POINTER(pcap_if_t)),
                      ct.c_char_p)(
                      ("pcap_findalldevs", dll), (
                      (1, "alldevsp"),
                      (1, "errbuf"),))

freealldevs   = CFUNC(None,
                      ct.POINTER(pcap_if_t))(
                      ("pcap_freealldevs", dll), (
                      (1, "alldevs"),))

lib_version   = CFUNC(ct.c_char_p)(
                      ("pcap_lib_version", dll),)

if is_windows:

    # Win32 definitions

    try:
        wsockinit = CFUNC(ct.c_int)(("pcap_wsockinit", dll),)
    except: pass

    #if defined("WPCAP"):

    import ctypes.wintypes

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

    #
    # Exported functions
    #

    setbuff            = CFUNC(ct.c_int,
                               ct.POINTER(pcap_t),
                               ct.c_int)(
                               ("pcap_setbuff", dll), (
                               (1, "pcap"),
                               (1, "dim"),))

    setmode            = CFUNC(ct.c_int,
                               ct.POINTER(pcap_t),
                               ct.c_int)(
                               ("pcap_setmode", dll), (
                               (1, "pcap"),
                               (1, "mode"),))

    setmintocopy       = CFUNC(ct.c_int,
                               ct.POINTER(pcap_t),
                               ct.c_int)(
                               ("pcap_setmintocopy", dll), (
                               (1, "pcap"),
                               (1, "size"),))

    getevent           = CFUNC(ct.wintypes.HANDLE,
                               ct.POINTER(pcap_t))(
                               ("pcap_getevent", dll), (
                               (1, "pcap"),))

    try:
        oid_get_request = CFUNC(ct.c_int,
                               ct.POINTER(pcap_t),
                               bpf_u_int32,
                               ct.c_void_p,
                               ct.c_size_t)(
                               ("pcap_oid_get_request", dll), (
                               (1, "pcap"),
                               (1, "oid"),
                               (1, "data"),
                               (1, "length"),))
    except: pass

    try:
        oid_set_request = CFUNC(ct.c_int,
                               ct.POINTER(pcap_t),
                               bpf_u_int32,
                               ct.c_void_p,
                               ct.c_size_t)(
                               ("pcap_oid_set_request", dll), (
                               (1, "pcap"),
                               (1, "oid"),
                               (1, "data"),
                               (1, "length"),))
    except: pass

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

    MODE_CAPT = 0
    MODE_STAT = 1
    MODE_MON  = 2

elif defined("MSDOS"):

    # MS-DOS definitions

    stats_ex  = CFUNC(ct.c_int,
                      ct.POINTER(pcap_t),
                      ct.POINTER(stat_ex))(
                      ("pcap_stats_ex", dll), (
                      (1, "pcap"),
                      (1, "stat"),))

    set_wait  = CFUNC(None,
                      ct.POINTER(pcap_t),
                      CFUNC(None),
                      ct.c_int)(
                      ("pcap_set_wait", dll), (
                      (1, "pcap"),
                      (1, "yield"),
                      (1, "wait"),))

    mac_packets = CFUNC(ct.c_ulong)(
                      ("pcap_mac_packets", dll),)

else: # UN*X

    # UN*X definitions

    get_selectable_fd = CFUNC(ct.c_int,
                              ct.POINTER(pcap_t))(
                              ("pcap_get_selectable_fd", dll), (
                              (1, "pcap"),))

#endif # WIN32/MSDOS/UN*X

if defined("HAVE_REMOTE"):
    # Includes most of the public stuff that is needed for the remote capture
    from ._remote_ext import *

# eof
