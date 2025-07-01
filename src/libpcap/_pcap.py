# flake8-in-file-ignores: noqa: E305,E722,F401

# Copyright (c) 2016 Adam Karpierz
# SPDX-License-Identifier: BSD-3-Clause

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

# Remote packet capture mechanisms and extensions from WinPcap:
#
# Copyright (c) 2002 - 2003
# NetGroup, Politecnico di Torino (Italy)
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
# 3. Neither the name of the Politecnico di Torino nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
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

import ctypes as ct

from ._platform import is_windows, is_linux, defined
from ._platform import CFUNC
from ._platform import timeval, SOCKET, INVALID_SOCKET, sockaddr
from ._platform import SOCKET as PCAP_SOCKET
from ._dll      import dll
if is_windows:  import msvcrt

from ._bpf import PCAP_DEPRECATED, BPF_RELEASE, bpf_program
from ._bpf import *  # noqa

intptr_t = (ct.c_int32 if ct.sizeof(ct.c_void_p) == ct.sizeof(ct.c_int32) else ct.c_int64)


class FILE(ct.Structure): pass

# Version number of the current version of the pcap file format.
#
# NOTE: this is *NOT* the version number of the libpcap library.
# To fetch the version information for the version of libpcap
# you're using, use pcap.lib_version().

PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4

PCAP_ERRBUF_SIZE = 256

# Compatibility for systems that have a bpf.h that
# predates the bpf typedefs for 64-bit support.

if not defined("BPF_RELEASE") or BPF_RELEASE < 199406:
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
# Documentation: https://www.tcpdump.org/manpages/pcap-savefile.5.txt.
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
#    https://github.com/the-tcpdump-group/libpcap/tree/master
#
# and issuing a pull request, so that future versions of libpcap and
# programs that use it (such as tcpdump) will be able to read your new
# capture file format.

class file_header(ct.Structure):
    _fields_ = [
    ("magic",         bpf_u_int32),
    ("version_major", ct.c_ushort),
    ("version_minor", ct.c_ushort),
    ("thiszone",      bpf_int32),    # not used - SHOULD be filled with 0
    ("sigfigs",       bpf_u_int32),  # not used - SHOULD be filled with 0
    ("snaplen",       bpf_u_int32),  # max length saved portion of each pkt
    ("linktype",      bpf_u_int32),  # data link type (LINKTYPE_*)
]

# Subfields of the field containing the link-layer header type.
#
# Link-layer header types are assigned for both pcap and
# pcapng, and the same value must work with both.  In pcapng,
# the link-layer header type field in an Interface Description
# Block is 16 bits, so only the bottommost 16 bits of the
# link-layer header type in a pcap file can be used for the
# header type value.
#
# In libpcap, the upper 16 bits, from the top down, are divided into:
#
#    A 4-bit "FCS length" field, to allow the FCS length to
#    be specified, just as it can be specified in the if_fcslen
#    field of the pcapng IDB.  The field is in units of 16 bits,
#    i.e. 1 means 16 bits of FCS, 2 means 32 bits of FCS, etc..
#
#    A reserved bit, which must be zero.
#
#    An "FCS length present" flag; if 0, the "FCS length" field
#    should be ignored, and if 1, the "FCS length" field should
#    be used.
#
#    10 reserved bits, which must be zero.  They were originally
#    intended to be used as a "class" field, allowing additional
#    classes of link-layer types to be defined, with a class value
#    of 0 indicating that the link-layer type is a LINKTYPE_ value.
#    A value of 0x224 was, at one point, used by NetBSD to define
#    "raw" packet types, with the lower 16 bits containing a
#    NetBSD AF_ value; see
#
#        https://marc.info/?l=tcpdump-workers&m=98296750229149&w=2
#
#    It's unknown whether those were ever used in capture files,
#    or if the intent was just to use it as a link-layer type
#    for BPF programs; NetBSD's libpcap used to support them in
#    the BPF code generator, but it no longer does so.  If it
#    was ever used in capture files, or if classes other than
#    "LINKTYPE_ value" are ever useful in capture files, we could
#    re-enable this, and use the reserved 16 bits following the
#    link-layer type in pcapng files to hold the class information
#    there.  (Note, BTW, that LINKTYPE_RAW/DLT_RAW is now being
#    interpreted by libpcap, tcpdump, and Wireshark as "raw IP",
#    including both IPv4 and IPv6, with the version number in the
#    header being checked to see which it is, not just "raw IPv4";
#    there are LINKTYPE_IPV4/DLT_IPV4 and LINKTYPE_IPV6/DLT_IPV6
#    values if "these are IPv{4,6} and only IPv{4,6} packets"
#    types are needed.)
#
#    Or we might be able to use it for other purposes.

LT_LINKTYPE           = lambda x: (x & 0x0000FFFF)
LT_LINKTYPE_EXT       = lambda x: (x & 0xFFFF0000)
LT_RESERVED1          = lambda x: (x & 0x03FF0000)
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
#
# caplen is the number of packet bytes available in the packet.
#
# len is the number of bytes that would have been available if
# the capture process had not discarded data at the end of the
# packet, either because a snapshot length less than the packet
# size was provided or because the mechanism used to capture
# the packet imposed a limit on the amount of packet data
# that is provided.

class pkthdr(ct.Structure):
    _fields_ = [
    ("ts",     timeval),      # time stamp
    ("caplen", bpf_u_int32),  # length of portion present in data
    ("len",    bpf_u_int32),  # length of this packet prior to any slicing
]

#
# As returned by the pcap.stats()
#

class stat(ct.Structure): pass
_fields_ = [
    ("ps_recv",   ct.c_uint),  # number of packets received
    ("ps_drop",   ct.c_uint),  # number of packets dropped
    ("ps_ifdrop", ct.c_uint),  # drops by interface -- only supported on some platforms
]
if is_windows:
    _fields_ += [
        ("ps_capt",    ct.c_uint),  # number of packets that reach the application
        ("ps_sent",    ct.c_uint),  # number of packets sent by the server on the network
        ("ps_netdrop", ct.c_uint),  # number of packets lost on the network
    ]
stat._fields_ = _fields_

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

PCAP_IF_LOOPBACK                         = 0x00000001  # interface is loopback
PCAP_IF_UP                               = 0x00000002  # interface is up      # avail. from v.1.8.1
PCAP_IF_RUNNING                          = 0x00000004  # interface is running # avail. from v.1.8.1
PCAP_IF_WIRELESS                         = 0x00000008  # interface is wireless (*NOT* necessarily Wi-Fi!)  # noqa: E501
PCAP_IF_CONNECTION_STATUS                = 0x00000030  # connection status:
PCAP_IF_CONNECTION_STATUS_UNKNOWN        = 0x00000000  # unknown
PCAP_IF_CONNECTION_STATUS_CONNECTED      = 0x00000010  # connected
PCAP_IF_CONNECTION_STATUS_DISCONNECTED   = 0x00000020  # disconnected
PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE = 0x00000030  # not applicable

pcap_handler = CFUNC(None, ct.POINTER(ct.c_ubyte), ct.POINTER(pkthdr), ct.POINTER(ct.c_ubyte))

# Error codes for the pcap API.
# These will all be negative, so you can check for the success or
# failure of a call that returns these codes by checking for a
# negative value.

PCAP_ERROR                         = -1   # generic error code
PCAP_ERROR_BREAK                   = -2   # loop terminated by pcap.breakloop
PCAP_ERROR_NOT_ACTIVATED           = -3   # the capture needs to be activated
PCAP_ERROR_ACTIVATED               = -4   # the operation can't be performed on already activated captures  # noqa: E501
PCAP_ERROR_NO_SUCH_DEVICE          = -5   # no such device exists
PCAP_ERROR_RFMON_NOTSUP            = -6   # this device doesn't support rfmon (monitor) mode
PCAP_ERROR_NOT_RFMON               = -7   # operation supported only in monitor mode
PCAP_ERROR_PERM_DENIED             = -8   # no permission to open the device
PCAP_ERROR_IFACE_NOT_UP            = -9   # interface isn't up
PCAP_ERROR_CANTSET_TSTAMP_TYPE     = -10  # this device doesn't support setting the time stamp type  # avail. from v.1.8.1  # noqa: E501
PCAP_ERROR_PROMISC_PERM_DENIED     = -11  # you don't have permission to capture in promiscuous mode # avail. from v.1.8.1  # noqa: E501
PCAP_ERROR_TSTAMP_PRECISION_NOTSUP = -12  # the requested time stamp precision is not supported      # avail. from v.1.8.1  # noqa: E501
PCAP_ERROR_CAPTURE_NOTSUP          = -13  # capture mechanism not available

# Warning codes for the pcap API.
# These will all be positive and non-zero, so they won't look like
# errors.

PCAP_WARNING                    = 1  # generic warning code
PCAP_WARNING_PROMISC_NOTSUP     = 2  # this device doesn't support promiscuous mode
PCAP_WARNING_TSTAMP_TYPE_NOTSUP = 3  # the requested time stamp type is not supported # avail. from v.1.8.1  # noqa: E501

# Value to pass to pcap.compile() as the netmask if you don't know what
# the netmask is.

PCAP_NETMASK_UNKNOWN = 0xFFFFFFFF  # avail. from v.1.8.1

# Initialize pcap.  If this isn't called, pcap is initialized to
# a mode source-compatible and binary-compatible with older versions
# that lack this routine.

# Initialization options.
# All bits not listed here are reserved for expansion.
#
# On UNIX-like systems, the local character encoding is assumed to be
# UTF-8, so no character encoding transformations are done.
#
# On Windows, the local character encoding is the local ANSI code page.

PCAP_CHAR_ENC_LOCAL = 0x00000000  # strings are in the local character encoding
PCAP_CHAR_ENC_UTF_8 = 0x00000001  # strings are in UTF-8
PCAP_MMAP_32BIT     = 0x00000002  # map packet buffers with 32-bit addresses

try:  # PCAP_AVAILABLE_1_10
    init = CFUNC(ct.c_int,
        ct.c_uint,
        ct.c_char_p)(
        ("pcap_init", dll), (
        (1, "pcap"),
        (1, "rfmon"),))
except: pass

# Time stamp types. # avail. from v.1.8.1
# Not all systems and interfaces will necessarily support all of these.
#
# A system that supports PCAP_TSTAMP_HOST is offering time stamps
# provided by the host machine, rather than by the capture device,
# but not committing to any characteristics of the time stamp.
#
# PCAP_TSTAMP_HOST_LOWPREC is a time stamp, provided by the host machine,
# that's low-precision but relatively cheap to fetch; it's normally done
# using the system clock, so it's normally synchronized with times you'd
# fetch from system calls.
#
# PCAP_TSTAMP_HOST_HIPREC is a time stamp, provided by the host machine,
# that's high-precision; it might be more expensive to fetch.  It is
# synchronized with the system clock.
#
# PCAP_TSTAMP_HOST_HIPREC_UNSYNCED is a time stamp, provided by the host
# machine, that's high-precision; it might be more expensive to fetch.
# It is not synchronized with the system clock, and might have
# problems with time stamps for packets received on different CPUs,
# depending on the platform.  It might be more likely to be strictly
# monotonic than PCAP_TSTAMP_HOST_HIPREC.
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

PCAP_TSTAMP_HOST                 = 0  # host-provided, unknown characteristics
PCAP_TSTAMP_HOST_LOWPREC         = 1  # host-provided, low precision, synced with the system clock
PCAP_TSTAMP_HOST_HIPREC          = 2  # host-provided, high precision, synced with the system clock
PCAP_TSTAMP_ADAPTER              = 3  # device-provided, synced with the system clock
PCAP_TSTAMP_ADAPTER_UNSYNCED     = 4  # device-provided, not synced with the system clock
PCAP_TSTAMP_HOST_HIPREC_UNSYNCED = 5  # host-provided, high prec., not synced with the system clock

# Time stamp resolution types.
# Not all systems and interfaces will necessarily support all of these
# resolutions when doing live captures; all of them can be requested
# when reading a savefile.

PCAP_TSTAMP_PRECISION_MICRO = 0  # use timestamps with microsecond precision, default
PCAP_TSTAMP_PRECISION_NANO  = 1  # use timestamps with nanosecond precision

#
# Exported functions
#

# From v.1.9.0 we're deprecating pcap.lookupdev() for various
# reasons (not thread-safe, can behave weirdly with WinPcap).
# Callers should use  pcap.findalldevs() and use the first device.
#
try:  # PCAP_AVAILABLE_0_4
    lookupdev = CFUNC(ct.c_char_p,
        ct.c_char_p)(
        ("pcap_lookupdev", dll), (
        (1, "errbuf"),))
    PCAP_DEPRECATED(lookupdev,
                    "use 'pcap.findalldevs' and use the first device")
except: pass

try:  # PCAP_AVAILABLE_0_4
    lookupnet = CFUNC(ct.c_int,
        ct.c_char_p,
        ct.POINTER(bpf_u_int32),
        ct.POINTER(bpf_u_int32),
        ct.c_char_p)(
        ("pcap_lookupnet", dll), (
        (1, "device"),
        (1, "netp"),
        (1, "maskp"),
        (1, "errbuf"),))
except: pass

try:  # PCAP_AVAILABLE_1_0
    create = CFUNC(ct.POINTER(pcap_t),
        ct.c_char_p,
        ct.c_char_p)(
        ("pcap_create", dll), (
        (1, "source"),
        (1, "errbuf"),))
except: pass

try:  # PCAP_AVAILABLE_1_0
    set_snaplen = CFUNC(ct.c_int,
        ct.POINTER(pcap_t),
        ct.c_int)(
        ("pcap_set_snaplen", dll), (
        (1, "pcap"),
        (1, "snaplen"),))
except: pass

try:  # PCAP_AVAILABLE_1_0
    set_promisc = CFUNC(ct.c_int,
        ct.POINTER(pcap_t),
        ct.c_int)(
        ("pcap_set_promisc", dll), (
        (1, "pcap"),
        (1, "promisc"),))
except: pass

try:  # PCAP_AVAILABLE_1_0
    can_set_rfmon = CFUNC(ct.c_int,
        ct.POINTER(pcap_t))(
        ("pcap_can_set_rfmon", dll), (
        (1, "pcap"),))
except: pass

try:  # PCAP_AVAILABLE_1_0
    set_rfmon = CFUNC(ct.c_int,
        ct.POINTER(pcap_t),
        ct.c_int)(
        ("pcap_set_rfmon", dll), (
        (1, "pcap"),
        (1, "rfmon"),))
except: pass

try:  # PCAP_AVAILABLE_1_0
    set_timeout = CFUNC(ct.c_int,
        ct.POINTER(pcap_t),
        ct.c_int)(
        ("pcap_set_timeout", dll), (
        (1, "pcap"),
        (1, "timeout"),))
except: pass

try:  # PCAP_AVAILABLE_1_2
    set_tstamp_type = CFUNC(ct.c_int,
        ct.POINTER(pcap_t),
        ct.c_int)(
        ("pcap_set_tstamp_type", dll), (
        (1, "pcap"),
        (1, "tstamp_type"),))
except: pass

try:  # PCAP_AVAILABLE_1_5
    set_immediate_mode = CFUNC(ct.c_int,
        ct.POINTER(pcap_t),
        ct.c_int)(
        ("pcap_set_immediate_mode", dll), (
        (1, "pcap"),
        (1, "immediate"),))
except: pass

try:  # PCAP_AVAILABLE_1_0
    set_buffer_size = CFUNC(ct.c_int,
        ct.POINTER(pcap_t),
        ct.c_int)(
        ("pcap_set_buffer_size", dll), (
        (1, "pcap"),
        (1, "buffer_size"),))
except: pass

try:  # PCAP_AVAILABLE_1_5
    set_tstamp_precision = CFUNC(ct.c_int,
        ct.POINTER(pcap_t),
        ct.c_int)(
        ("pcap_set_tstamp_precision", dll), (
        (1, "pcap"),
        (1, "tstamp_precision"),))
except: pass

try:  # PCAP_AVAILABLE_1_5
    get_tstamp_precision = CFUNC(ct.c_int,
        ct.POINTER(pcap_t))(
        ("pcap_get_tstamp_precision", dll), (
        (1, "pcap"),))
except: pass

try:  # PCAP_AVAILABLE_1_2
    list_tstamp_types = CFUNC(ct.c_int,
        ct.POINTER(pcap_t),
        ct.POINTER(ct.POINTER(ct.c_int)))(
        ("pcap_list_tstamp_types", dll), (
        (1, "pcap"),
        (1, "tstamp_type_list"),))
except: pass

try:  # PCAP_AVAILABLE_1_2
    free_tstamp_types = CFUNC(None,
        ct.POINTER(ct.c_int))(
        ("pcap_free_tstamp_types", dll), (
        (1, "tstamp_type_list"),))
except: pass

try:  # PCAP_AVAILABLE_1_2
    tstamp_type_name_to_val = CFUNC(ct.c_int,
        ct.c_char_p)(
        ("pcap_tstamp_type_name_to_val", dll), (
        (1, "name"),))
except: pass

try:  # PCAP_AVAILABLE_1_2
    tstamp_type_val_to_name = CFUNC(ct.c_char_p,
        ct.c_int)(
        ("pcap_tstamp_type_val_to_name", dll), (
        (1, "tstamp_type"),))
except: pass

try:  # PCAP_AVAILABLE_1_2
    tstamp_type_val_to_description = CFUNC(ct.c_char_p,
        ct.c_int)(
        ("pcap_tstamp_type_val_to_description", dll), (
        (1, "tstamp_type"),))
except: pass

if is_linux:
    try:  # PCAP_AVAILABLE_1_9
        set_protocol_linux = CFUNC(ct.c_int,
            ct.POINTER(pcap_t),
            ct.c_int)(
            ("pcap_set_protocol_linux", dll), (
            (1, "pcap"),
            (1, "protocol"),))
    except: pass

try:  # PCAP_AVAILABLE_1_0
    activate = CFUNC(ct.c_int,
        ct.POINTER(pcap_t))(
        ("pcap_activate", dll), (
        (1, "pcap"),))
except: pass

try:  # PCAP_AVAILABLE_0_4
    open_live = CFUNC(ct.POINTER(pcap_t),
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
except: pass

try:  # PCAP_AVAILABLE_0_6
    open_dead = CFUNC(ct.POINTER(pcap_t),
        ct.c_int,
        ct.c_int)(
        ("pcap_open_dead", dll), (
        (1, "linktype"),
        (1, "snaplen"),))
except: pass

try:  # PCAP_AVAILABLE_1_5
    open_dead_with_tstamp_precision = CFUNC(ct.POINTER(pcap_t),
        ct.c_int,
        ct.c_int,
        ct.c_uint)(
        ("pcap_open_dead_with_tstamp_precision", dll), (
        (1, "linktype"),
        (1, "snaplen"),
        (1, "precision"),))
except: pass

try:  # PCAP_AVAILABLE_0_4
    open_offline  = CFUNC(ct.POINTER(pcap_t),
        ct.c_char_p,
        ct.c_char_p)(
        ("pcap_open_offline", dll), (
        (1, "fname"),
        (1, "errbuf"),))
except: pass

try:  # PCAP_AVAILABLE_1_5
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

    # @CFUNC(ct.POINTER(pcap_t), ct.POINTER(FILE), ct.c_char_p)
    def fopen_offline(fp, errbuf, libc=ct.cdll.msvcrt):
        return hopen_offline(msvcrt.get_osfhandle(libc._fileno(fp)), errbuf)

    try:  # PCAP_AVAILABLE_1_5
        hopen_offline_with_tstamp_precision = CFUNC(ct.POINTER(pcap_t),
            intptr_t,
            ct.c_uint,
            ct.c_char_p)(
            ("pcap_hopen_offline_with_tstamp_precision", dll), (
            (1, "osfd"),
            (1, "precision"),
            (1, "errbuf"),))

        # @CFUNC(ct.POINTER(pcap_t), ct.POINTER(FILE), ct.c_uint, ct.c_char_p)
        def fopen_offline_with_tstamp_precision(fp, precision, errbuf, libc=ct.cdll.msvcrt):
            return hopen_offline_with_tstamp_precision(msvcrt.get_osfhandle(libc._fileno(fp)),
                                                       precision, errbuf)
    except: pass
else:
    try:  # PCAP_AVAILABLE_0_9
        fopen_offline = CFUNC(ct.POINTER(pcap_t),
            ct.POINTER(FILE),
            ct.c_char_p)(
            ("pcap_fopen_offline", dll), (
            (1, "fp"),
            (1, "errbuf"),))
    except: pass

    try:  # PCAP_AVAILABLE_1_5
        fopen_offline_with_tstamp_precision = CFUNC(ct.POINTER(pcap_t),
            ct.POINTER(FILE),
            ct.c_uint,
            ct.c_char_p)(
            ("pcap_fopen_offline_with_tstamp_precision", dll), (
            (1, "fp"),
            (1, "precision"),
            (1, "errbuf"),))
    except: pass

try:  # PCAP_AVAILABLE_0_4
    close = CFUNC(None,
        ct.POINTER(pcap_t))(
        ("pcap_close", dll), (
        (1, "pcap"),))
except: pass

try:  # PCAP_AVAILABLE_0_4
    loop = CFUNC(ct.c_int,
        ct.POINTER(pcap_t),
        ct.c_int,
        pcap_handler,
        ct.POINTER(ct.c_ubyte))(
        ("pcap_loop", dll), (
        (1, "pcap"),
        (1, "cnt"),
        (1, "callback"),
        (1, "user"),))
except: pass

try:  # PCAP_AVAILABLE_0_4
    dispatch  = CFUNC(ct.c_int,
        ct.POINTER(pcap_t),
        ct.c_int,
        pcap_handler,
        ct.POINTER(ct.c_ubyte))(
        ("pcap_dispatch", dll), (
        (1, "pcap"),
        (1, "cnt"),
        (1, "callback"),
        (1, "user"),))
except: pass

try:  # PCAP_AVAILABLE_0_4
    next = CFUNC(ct.POINTER(ct.c_ubyte),  # noqa: A001
        ct.POINTER(pcap_t),
        ct.POINTER(pkthdr))(
        ("pcap_next", dll), (
        (1, "pcap"),
        (1, "pkt_header"),))
except: pass

try:  # PCAP_AVAILABLE_0_8
    next_ex = CFUNC(ct.c_int,
        ct.POINTER(pcap_t),
        ct.POINTER(ct.POINTER(pkthdr)),
        ct.POINTER(ct.POINTER(ct.c_ubyte)))(
        ("pcap_next_ex", dll), (
        (1, "pcap"),
        (1, "pkt_header"),
        (1, "pkt_data"),))
except: pass

try:  # PCAP_AVAILABLE_0_8
    breakloop = CFUNC(None,
        ct.POINTER(pcap_t))(
        ("pcap_breakloop", dll), (
        (1, "pcap"),))
except: pass

try:  # PCAP_AVAILABLE_0_4
    stats = CFUNC(ct.c_int,
        ct.POINTER(pcap_t),
        ct.POINTER(stat))(
        ("pcap_stats", dll), (
        (1, "pcap"),
        (1, "stat"),))
except: pass

try:  # PCAP_AVAILABLE_0_4
    setfilter = CFUNC(ct.c_int,
        ct.POINTER(pcap_t),
        ct.POINTER(bpf_program))(
        ("pcap_setfilter", dll), (
        (1, "pcap"),
        (1, "prog"),))
except: pass

try:  # PCAP_AVAILABLE_0_9
    setdirection = CFUNC(ct.c_int,
        ct.POINTER(pcap_t),
        direction_t)(
        ("pcap_setdirection", dll), (
        (1, "pcap"),
        (1, "direction"),))
except: pass

try:  # PCAP_AVAILABLE_0_7
    getnonblock = CFUNC(ct.c_int,
        ct.POINTER(pcap_t),
        ct.c_char_p)(
        ("pcap_getnonblock", dll), (
        (1, "pcap"),
        (1, "errbuf"),))
except: pass

try:  # PCAP_AVAILABLE_0_7
    setnonblock = CFUNC(ct.c_int,
        ct.POINTER(pcap_t),
        ct.c_int,
        ct.c_char_p)(
        ("pcap_setnonblock", dll), (
        (1, "pcap"),
        (1, "nonblock"),
        (1, "errbuf"),))
except: pass

try:  # PCAP_AVAILABLE_0_9
    inject = CFUNC(ct.c_int,
        ct.POINTER(pcap_t),
        ct.c_void_p,
        ct.c_size_t)(
        ("pcap_inject", dll), (
        (1, "pcap"),
        (1, "buffer"),
        (1, "size"),))
except: pass

try:  # PCAP_AVAILABLE_0_8
    sendpacket = CFUNC(ct.c_int,
        ct.POINTER(pcap_t),
        ct.POINTER(ct.c_ubyte),
        ct.c_int)(
        ("pcap_sendpacket", dll), (
        (1, "pcap"),
        (1, "buffer"),
        (1, "size"),))
except: pass

try:  # PCAP_AVAILABLE_1_0
    statustostr = CFUNC(ct.c_char_p,
        ct.c_int)(
        ("pcap_statustostr", dll), (
        (1, "errnum"),))
except: pass

try:  # PCAP_AVAILABLE_0_4
    strerror  = CFUNC(ct.c_char_p,
        ct.c_int)(
        ("pcap_strerror", dll), (
        (1, "errnum"),))
except: pass

try:  # PCAP_AVAILABLE_0_4
    geterr = CFUNC(ct.c_char_p,
        ct.POINTER(pcap_t))(
        ("pcap_geterr", dll), (
        (1, "pcap"),))
except: pass

try:  # PCAP_AVAILABLE_0_4
    perror = CFUNC(None,
        ct.POINTER(pcap_t),
        ct.c_char_p)(
        ("pcap_perror", dll), (
        (1, "pcap"),
        (1, "prefix"),))
except: pass

try:  # PCAP_AVAILABLE_0_4
    compile = CFUNC(ct.c_int,  # noqa: A001
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
except: pass

try:  # PCAP_AVAILABLE_0_5
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
    PCAP_DEPRECATED(compile_nopcap,
                    "use pcap.open_dead(), pcap.compile() and pcap.close()")
except: pass

try:  # PCAP_AVAILABLE_0_6 (XXX - this took two arguments in 0.4 and 0.5)
    freecode  = CFUNC(None,
        ct.POINTER(bpf_program))(
        ("pcap_freecode", dll), (
        (1, "prog"),))
except: pass

try:  # PCAP_AVAILABLE_1_0
    offline_filter = CFUNC(ct.c_int,
        ct.POINTER(bpf_program),
        ct.POINTER(pkthdr),
        ct.POINTER(ct.c_ubyte))(
        ("pcap_offline_filter", dll), (
        (1, "prog"),
        (1, "pkt_header"),
        (1, "pkt_data"),))
except: pass

try:  # PCAP_AVAILABLE_0_4
    datalink = CFUNC(ct.c_int,
        ct.POINTER(pcap_t))(
        ("pcap_datalink", dll), (
        (1, "pcap"),))
except: pass

try:  # PCAP_AVAILABLE_1_0
    datalink_ext = CFUNC(ct.c_int,
        ct.POINTER(pcap_t))(
        ("pcap_datalink_ext", dll), (
        (1, "pcap"),))
except: pass

try:  # PCAP_AVAILABLE_0_8
    list_datalinks = CFUNC(ct.c_int,
        ct.POINTER(pcap_t),
        ct.POINTER(ct.POINTER(ct.c_int)))(
        ("pcap_list_datalinks", dll), (
        (1, "pcap"),
        (1, "dlt_buffer"),))
except: pass

try:  # PCAP_AVAILABLE_0_8
    set_datalink = CFUNC(ct.c_int,
        ct.POINTER(pcap_t),
        ct.c_int)(
        ("pcap_set_datalink", dll), (
        (1, "pcap"),
        (1, "dlt"),))
except: pass

try:  # PCAP_AVAILABLE_0_8
    free_datalinks = CFUNC(None,
        ct.POINTER(ct.c_int))(
        ("pcap_free_datalinks", dll), (
        (1, "dlt_list"),))
except: pass

try:  # PCAP_AVAILABLE_0_8
    datalink_name_to_val = CFUNC(ct.c_int,
        ct.c_char_p)(
        ("pcap_datalink_name_to_val", dll), (
        (1, "name"),))
except: pass

try:  # PCAP_AVAILABLE_0_8
    datalink_val_to_name = CFUNC(ct.c_char_p,
        ct.c_int)(
        ("pcap_datalink_val_to_name", dll), (
        (1, "dlt"),))
except: pass

try:  # PCAP_AVAILABLE_0_8
    datalink_val_to_description = CFUNC(ct.c_char_p,
        ct.c_int)(
        ("pcap_datalink_val_to_description", dll), (
        (1, "dlt"),))
except: pass

try:  # PCAP_AVAILABLE_1_9
    datalink_val_to_description_or_dlt = CFUNC(ct.c_char_p,
        ct.c_int)(
        ("pcap_datalink_val_to_description_or_dlt", dll), (
        (1, "dlt"),))
except: pass

try:  # PCAP_AVAILABLE_0_4
    snapshot  = CFUNC(ct.c_int,
        ct.POINTER(pcap_t))(
        ("pcap_snapshot", dll), (
        (1, "pcap"),))
except: pass

try:  # PCAP_AVAILABLE_0_4
    is_swapped = CFUNC(ct.c_int,
        ct.POINTER(pcap_t))(
        ("pcap_is_swapped", dll), (
        (1, "pcap"),))
except: pass

try:  # PCAP_AVAILABLE_1_9
    bufsize = CFUNC(ct.c_int,
        ct.POINTER(pcap_t))(
        ("pcap_bufsize", dll), (
        (1, "pcap"),))
except: pass

try:  # PCAP_AVAILABLE_0_4
    major_version = CFUNC(ct.c_int,
        ct.POINTER(pcap_t))(
        ("pcap_major_version", dll), (
        (1, "pcap"),))
except: pass

try:  # PCAP_AVAILABLE_0_4
    minor_version = CFUNC(ct.c_int,
        ct.POINTER(pcap_t))(
        ("pcap_minor_version", dll), (
        (1, "pcap"),))
except: pass

# XXX
try:  # PCAP_AVAILABLE_0_4
    file = CFUNC(ct.POINTER(FILE),
        ct.POINTER(pcap_t))(
        ("pcap_file", dll), (
        (1, "pcap"),))
except: pass

try:  # PCAP_AVAILABLE_0_4
    fileno = CFUNC(ct.c_int,
        ct.POINTER(pcap_t))(
        ("pcap_fileno", dll), (
        (1, "pcap"),))
    if is_windows:
        # This probably shouldn't have been kept in WinPcap; most if not all
        # UN*X code that used it won't work on Windows.  We deprecate it; if
        # anybody really needs access to whatever HANDLE may be associated
        # with a pcap_t (there's no guarantee that there is one), we can add
        # a Windows-only pcap_handle() API that returns the HANDLE.
        #
        PCAP_DEPRECATED(fileno,
                        "request a 'pcap_handle' that returns a HANDLE if you need it")
except: pass

try:  # PCAP_AVAILABLE_0_4
    dump_open = CFUNC(ct.POINTER(pcap_dumper_t),
        ct.POINTER(pcap_t),
        ct.c_char_p)(
        ("pcap_dump_open", dll), (
        (1, "pcap"),
        (1, "fname"),))
except: pass

try:  # PCAP_AVAILABLE_1_7
    dump_open_append = CFUNC(ct.POINTER(pcap_dumper_t),
        ct.POINTER(pcap_t),
        ct.c_char_p)(
        ("pcap_dump_open_append", dll), (
        (1, "pcap"),
        (1, "fname"),))
except: pass

if is_windows:
    try:  # PCAP_AVAILABLE_0_9
        dump_hopen = CFUNC(ct.POINTER(pcap_dumper_t),
            ct.POINTER(pcap_t),
            intptr_t)(
            ("pcap_dump_hopen", dll), (
            (1, "pcap"),
            (1, "osfd"),))

        # If we're building libpcap, this is an internal routine in sf-pcap.c, so
        # we must not define it as a macro.
        #
        # If we're not building libpcap, given that the version of the C runtime
        # with which libpcap was built might be different from the version
        # of the C runtime with which an application using libpcap was built,
        # and that a FILE structure may differ between the two versions of the
        # C runtime, calls to _fileno() must use the version of _fileno() in
        # the C runtime used to open the FILE *, not the version in the C
        # runtime with which libpcap was built.  (Maybe once the Universal CRT
        # rules the world, this will cease to be a problem.)

        # @CFUNC(ct.POINTER(pcap_dumper_t), ct.POINTER(pcap_t), ct.POINTER(FILE))
        def dump_fopen(pcap, fp, libc=ct.cdll.msvcrt):
            return dump_hopen(pcap, msvcrt.get_osfhandle(libc._fileno(fp)))
    except: pass
else:
    try:  # PCAP_AVAILABLE_0_9
        dump_fopen = CFUNC(ct.POINTER(pcap_dumper_t),
            ct.POINTER(pcap_t),
            ct.POINTER(FILE))(
            ("pcap_dump_fopen", dll), (
            (1, "pcap"),
            (1, "fp"),))
    except: pass

try:  # PCAP_AVAILABLE_0_8
    dump_file = CFUNC(ct.POINTER(FILE),
        ct.POINTER(pcap_dumper_t))(
        ("pcap_dump_file", dll), (
        (1, "pcap_dumper"),))
except: pass

try:  # PCAP_AVAILABLE_0_9
    dump_ftell = CFUNC(ct.c_long,
        ct.POINTER(pcap_dumper_t))(
        ("pcap_dump_ftell", dll), (
        (1, "pcap_dumper"),))
except: pass

try:  # PCAP_AVAILABLE_1_9
    dump_ftell64 = CFUNC(ct.c_int64,
        ct.POINTER(pcap_dumper_t))(
        ("pcap_dump_ftell64", dll), (
        (1, "pcap_dumper"),))
except: pass

try:  # PCAP_AVAILABLE_0_8
    dump_flush = CFUNC(ct.c_int,
        ct.POINTER(pcap_dumper_t))(
        ("pcap_dump_flush", dll), (
        (1, "pcap_dumper"),))
except: pass

try:  # PCAP_AVAILABLE_0_4
    dump_close = CFUNC(None,
        ct.POINTER(pcap_dumper_t))(
        ("pcap_dump_close", dll), (
        (1, "pcap_dumper"),))
except: pass

try:  # PCAP_AVAILABLE_0_4
    dump = CFUNC(None,
        ct.POINTER(ct.c_ubyte),
        ct.POINTER(pkthdr),
        ct.POINTER(ct.c_ubyte))(
        ("pcap_dump", dll), (
        (1, "fhandle"),
        (1, "pkt_header"),
        (1, "pkt_data"),))
except: pass

try:  # PCAP_AVAILABLE_0_7
    findalldevs = CFUNC(ct.c_int,
        ct.POINTER(ct.POINTER(pcap_if_t)),
        ct.c_char_p)(
        ("pcap_findalldevs", dll), (
        (1, "alldevsp"),
        (1, "errbuf"),))
except: pass

try:  # PCAP_AVAILABLE_0_7
    freealldevs = CFUNC(None,
        ct.POINTER(pcap_if_t))(
        ("pcap_freealldevs", dll), (
        (1, "alldevs"),))
except: pass

# We return a pointer to the version string, rather than exporting the
# version string directly.
#
# On at least some UNIXes, if you import data from a shared library into
# a program, the data is bound into the program binary, so if the string
# in the version of the library with which the program was linked isn't
# the same as the string in the version of the library with which the
# program is being run, various undesirable things may happen (warnings,
# the string being the one from the version of the library with which the
# program was linked, or even weirder things, such as the string being the
# one from the library but being truncated).
#
# On Windows, the string is constructed at run time.
#
try:  # PCAP_AVAILABLE_0_8
    lib_version = CFUNC(ct.c_char_p)(
        ("pcap_lib_version", dll),)
except: pass

if is_windows:

    # Win32 definitions

    try:
        wsockinit = CFUNC(ct.c_int)(
            ("pcap_wsockinit", dll),)
    except: pass

    # if defined("WPCAP"):

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

    setbuff = CFUNC(ct.c_int,
        ct.POINTER(pcap_t),
        ct.c_int)(
        ("pcap_setbuff", dll), (
        (1, "pcap"),
        (1, "dim"),))

    setmode = CFUNC(ct.c_int,
        ct.POINTER(pcap_t),
        ct.c_int)(
        ("pcap_setmode", dll), (
        (1, "pcap"),
        (1, "mode"),))

    setmintocopy = CFUNC(ct.c_int,
        ct.POINTER(pcap_t),
        ct.c_int)(
        ("pcap_setmintocopy", dll), (
        (1, "pcap"),
        (1, "size"),))

    getevent = CFUNC(ct.wintypes.HANDLE,
        ct.POINTER(pcap_t))(
        ("pcap_getevent", dll), (
        (1, "pcap"),))

    try:  # PCAP_AVAILABLE_1_8
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

    try:  # PCAP_AVAILABLE_1_8
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

    sendqueue_alloc = CFUNC(ct.POINTER(send_queue),
        ct.c_uint)(
        ("pcap_sendqueue_alloc", dll), (
        (1, "memsize"),))

    sendqueue_destroy = CFUNC(None,
        ct.POINTER(send_queue))(
        ("pcap_sendqueue_destroy", dll), (
        (1, "queue"),))

    sendqueue_queue = CFUNC(ct.c_int,
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

    stats_ex = CFUNC(ct.POINTER(stat),
        ct.POINTER(pcap_t),
        ct.POINTER(ct.c_int))(
        ("pcap_stats_ex", dll), (
        (1, "pcap"),
        (1, "stat_size"),))

    setuserbuffer = CFUNC(ct.c_int,
        ct.POINTER(pcap_t),
        ct.c_int)(
        ("pcap_setuserbuffer", dll), (
        (1, "pcap"),
        (1, "size"),))

    live_dump = CFUNC(ct.c_int,
        ct.POINTER(pcap_t),
        ct.c_char_p,
        ct.c_int,
        ct.c_int)(
        ("pcap_live_dump", dll), (
        (1, "pcap"),
        (1, "filename"),
        (1, "maxsize"),
        (1, "maxpacks"),))

    live_dump_ended = CFUNC(ct.c_int,
        ct.POINTER(pcap_t),
        ct.c_int)(
        ("pcap_live_dump_ended", dll), (
        (1, "pcap"),
        (1, "sync"),))

    try:
        start_oem = CFUNC(ct.c_int,
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
    PCAP_DEPRECATED(get_airpcap_handle,
                    "AirPcap support has been removed")

    MODE_CAPT = 0
    MODE_STAT = 1
    MODE_MON  = 2

else:  # UN*X

    # UN*X definitions

    try:  # PCAP_AVAILABLE_0_8
        get_selectable_fd = CFUNC(ct.c_int,
            ct.POINTER(pcap_t))(
            ("pcap_get_selectable_fd", dll), (
            (1, "pcap"),))
    except: pass

    try:  # PCAP_AVAILABLE_1_9
        get_required_select_timeout = CFUNC(ct.POINTER(timeval),
            ct.POINTER(pcap_t))(
            ("pcap_get_required_select_timeout", dll), (
            (1, "pcap"),))
    except: pass

# endif # _WIN32/UN*X

# APIs added in WinPcap for remote capture.
#
# They are present even if remote capture isn't enabled, as they
# also support local capture, and as their absence may complicate
# code build on macOS 14 with Xcode 15, as that platform supports
# "weakly linked symbols":
#
#    https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFrameworks/Concepts/WeakLinking.html
#
# which are symbols in dynamically-linked shared libraries, declared in
# such a fashion that if a program linked against a newer software
# development kit (SDK), and using a symbol present in the OS version
# for which that SDK is provided, is run on an older OS version that
# lacks that symbol, that symbol's value is a NULL pointer.  This
# allows those programs to test for the presence of that symbol
# by checking whether it's non-null and, if it is, using the symbol,
# otherwise not using it.
#
# (This is a slightly more convenient alternative to the usual
# technique used on Windows - and also available, and sometimes
# used, on UN*Xes - of loading the library containing the symbol
# at run time with dlopen() on UN*Xes and LoadLibrary() on Windows,
# looking up the symbol with dlsym() on UN*Xes and GetProcAddress()
# on Windows, and using the symbol with the returned pointer if it's
# not null.)

# The maximum buffer size in which address, port, interface names are kept.
#
# In case the adapter name or such is larger than this value, it is truncated.
# This is not used by the user; however it must be aware that an
# hostname / interface name longer than this value will be truncated.

PCAP_BUF_SIZE = 1024

# The type of input source, passed to pcap.open().

PCAP_SRC_FILE     = 2  # local savefile
PCAP_SRC_IFLOCAL  = 3  # local network interface
PCAP_SRC_IFREMOTE = 4  # interface on a remote host, using RPCAP

# The formats allowed by pcap.open() are the following (optional parts in []):
# - file://path_and_filename [opens a local file]
# - rpcap://devicename [opens the selected device available on the local host,
#   without using the RPCAP protocol]
# - rpcap://[username:password@]host[:port]/devicename [opens the selected device
#   available on a remote host]
#   - username and password, if present, will be used to authenticate to the remote host
#   - port, if present, will specify a port for RPCAP rather than using the default
# - adaptername [to open a local adapter; kept for compatibility, but it is
#   strongly discouraged]
# - (NULL) [to open the first local adapter; kept for compatibility, but it is
#   strongly discouraged]
#
# The formats allowed by the pcap.findalldevs_ex() are the following (optional parts in []):
# - file://folder/ [lists all the files in the given folder]
# - rpcap:// [lists all local adapters]
# - rpcap://[username:password@]host[:port]/ [lists the devices available on a remote host]
#   - username and password, if present, will be used to authenticate to the remote host
#   - port, if present, will specify a port for RPCAP rather than using the default
#
# In all the above, "rpcaps://" can be substituted for "rpcap://" to enable
# SSL (if it has been compiled in).
#
# Referring to the 'host' and 'port' parameters, they can be either numeric or
# literal. Since IPv6 is fully supported, these are the allowed formats:
#
# - host (literal): e.g. host.foo.bar
# - host (numeric IPv4): e.g. 10.11.12.13
# - host (numeric IPv4, IPv6 style): e.g. [10.11.12.13]
# - host (numeric IPv6): e.g. [1:2:3::4]
# - port: can be either numeric (e.g. '80') or literal (e.g. 'http')
#
# Here you find some allowed examples:
# - rpcap://host.foo.bar/devicename [everything literal, no port number]
# - rpcap://host.foo.bar:1234/devicename [everything literal, with port number]
# - rpcap://root:hunter2@host.foo.bar/devicename [everything literal, with username/password]
# - rpcap://10.11.12.13/devicename [IPv4 numeric, no port number]
# - rpcap://10.11.12.13:1234/devicename [IPv4 numeric, with port number]
# - rpcap://[10.11.12.13]:1234/devicename [IPv4 numeric with IPv6 format, with
#                                          port number]
# - rpcap://[1:2:3::4]/devicename [IPv6 numeric, no port number]
# - rpcap://[1:2:3::4]:1234/devicename [IPv6 numeric, with port number]
# - rpcap://[1:2:3::4]:http/devicename [IPv6 numeric, with literal port number]

# URL schemes for capture source.

# This string indicates that the user wants to open a capture from a
# local file.

PCAP_SRC_FILE_STRING = b"file://"

# This string indicates that the user wants to open a capture from a
# network interface.  This string does not necessarily involve the use
# of the RPCAP protocol.  If the interface required resides on the local
# host, the RPCAP protocol is not involved and the local functions are used.

PCAP_SRC_IF_STRING = b"rpcap://"

# Flags to pass to pcap.open().

# Specifies whether promiscuous mode is to be used.

PCAP_OPENFLAG_PROMISCUOUS = 0x00000001

# Specifies, for an RPCAP capture, whether the data transfer (in
# case of a remote capture) has to be done with UDP protocol.
#
# If it is '1' if you want a UDP data connection, '0' if you want
# a TCP data connection; control connection is always TCP-based.
# A UDP connection is much lighter, but it does not guarantee that all
# the captured packets arrive to the client workstation. Moreover,
# it could be harmful in case of network congestion.
# This flag is meaningless if the source is not a remote interface.
# In that case, it is simply ignored.

PCAP_OPENFLAG_DATATX_UDP = 0x00000002

# Specifies whether the remote probe will capture its own generated
# traffic.
#
# In case the remote probe uses the same interface to capture traffic
# and to send data back to the caller, the captured traffic includes
# the RPCAP traffic as well.  If this flag is turned on, the RPCAP
# traffic is excluded from the capture, so that the trace returned
# back to the collector is does not include this traffic.
#
# Has no effect on local interfaces or savefiles.

PCAP_OPENFLAG_NOCAPTURE_RPCAP = 0x00000004

# Specifies whether the local adapter will capture its own generated traffic.
#
# This flag tells the underlying capture driver to drop the packets
# that were sent by itself.  This is useful when building applications
# such as bridges that should ignore the traffic they just sent.
#
# Supported only on Windows.

PCAP_OPENFLAG_NOCAPTURE_LOCAL = 0x00000008

# This flag configures the adapter for maximum responsiveness.
#
# In presence of a large value for nbytes, WinPcap waits for the arrival
# of several packets before copying the data to the user. This guarantees
# a low number of system calls, i.e. lower processor usage, i.e. better
# performance, which is good for applications like sniffers. If the user
# sets the PCAP_OPENFLAG_MAX_RESPONSIVENESS flag, the capture driver will
# copy the packets as soon as the application is ready to receive them.
# This is suggested for real time applications (such as, for example,
# a bridge) that need the best responsiveness.
#
# The equivalent with pcap.create()/pcap.activate() is "immediate mode".

PCAP_OPENFLAG_MAX_RESPONSIVENESS = 0x00000010

# Remote authentication methods.
# These are used in the 'type' member of the pcap.rmtauth structure.

# NULL authentication.
#
# The 'NULL' authentication has to be equal to 'zero', so that old
# applications can just put every field of struct pcap.rmtauth to zero,
# and it does work.

RPCAP_RMTAUTH_NULL = 0

# Username/password authentication.
#
# With this type of authentication, the RPCAP protocol will use the username/
# password provided to authenticate the user on the remote machine. If the
# authentication is successful (and the user has the right to open network
# devices) the RPCAP connection will continue; otherwise it will be dropped.
#
# *******NOTE********: unless TLS is being used, the username and password
# are sent over the network to the capture server *IN CLEAR TEXT*.  Don't
# use this, without TLS (i.e., with rpcap:// rather than rpcaps://) on
# a network that you don't completely control!  (And be *really* careful
# in your definition of "completely"!)

RPCAP_RMTAUTH_PWD = 1

# This structure keeps the information needed to authenticate the user
# on a remote machine.
#
# The remote machine can either grant or refuse the access according
# to the information provided.
# In case the NULL authentication is required, both 'username' and
# 'password' can be NULL pointers.
#
# This structure is meaningless if the source is not a remote interface;
# in that case, the functions which requires such a structure can accept
# a NULL pointer as well.

class rmtauth(ct.Structure):
    _fields_ = [

    # Type of the authentication required.
    #
    # In order to provide maximum flexibility, we can support different types
    # of authentication based on the value of this 'type' variable.
    # The currently supported authentication methods are defined into the
    # Remote Authentication Methods Section.
    ("type", ct.c_int),

    # Zero-terminated string containing the username that has to be
    # used on the remote machine for authentication.
    #
    # This field is meaningless in case of the RPCAP_RMTAUTH_NULL
    # authentication and it can be NULL.
    ("username", ct.c_char_p),

    # Zero-terminated string containing the password that has to be
    # used on the remote machine for authentication.
    #
    # This field is meaningless in case of the RPCAP_RMTAUTH_NULL
    # authentication and it can be NULL.
    ("password", ct.c_char_p),
]

# Sampling methods.
#
# These allow pcap.loop(), pcap.dispatch(), pcap.next(), and pcap.next_ex()
# to see only a sample of packets, rather than all packets.
#
# Currently, they work only on Windows local captures.

# Specifies that no sampling is to be done on the current capture.
#
# In this case, no sampling algorithms are applied to the current capture.

PCAP_SAMP_NOSAMP = 0

# Specifies that only 1 out of N packets must be returned to the user.
#
# In this case, the 'value' field of the 'pcap.samp' structure indicates the
# number of packets (minus 1) that must be discarded before one packet got
# accepted.
# In other words, if 'value = 10', the first packet is returned to the
# caller, while the following 9 are discarded.

PCAP_SAMP_1_EVERY_N = 1

# Specifies that we have to return 1 packet every N milliseconds.
#
# In this case, the 'value' field of the 'pcap.samp' structure indicates
# the 'waiting time' in milliseconds before one packet got accepted.
# In other words, if 'value = 10', the first packet is returned to the
# caller; the next returned one will be the first packet that arrives
# when 10ms have elapsed.

PCAP_SAMP_FIRST_AFTER_N_MS = 2

# This structure defines the information related to sampling.
#
# In case the sampling is requested, the capturing device should read
# only a subset of the packets coming from the source. The returned packets
# depend on the sampling parameters.
#
# WARNING:
# The sampling process is applied *after* the filtering process.
# In other words, packets are filtered first, then the sampling process
# selects a subset of the 'filtered' packets and it returns them to the
# caller.

class samp(ct.Structure):
    _fields_ = [

    # Method used for sampling; see above.
    ("method", ct.c_int),

    # This value depends on the sampling method defined.
    # For its meaning, see above.
    ("value", ct.c_int),
]

# RPCAP active mode.

# Maximum length of an host name (needed for the RPCAP active mode)

RPCAP_HOSTLIST_SIZE = 1024

#
# Exported functions
#

# This routine can open a savefile, a local device, or a device on
# a remote machine running an RPCAP server.
#
# For opening a savefile, the pcap.open_offline routines can be used,
# and will work just as well; code using them will work on more
# platforms than code using pcap.open() to open savefiles.
#
# For opening a local device, pcap.open_live() can be used; it supports
# most of the capabilities that pcap.open() supports, and code using it
# will work on more platforms than code using pcap.open().  pcap.create()
# and pcap.activate() can also be used; they support all capabilities
# that pcap.open() supports, except for the Windows-only
# PCAP_OPENFLAG_NOCAPTURE_LOCAL, and support additional capabilities.
#
# For opening a remote capture, pcap.open() is currently the only
# API available.
#
try:  # PCAP_AVAILABLE_1_9_REMOTE
    # ifdef ENABLE_REMOTE
    open = CFUNC(ct.POINTER(pcap_t),  # noqa: A001
        ct.c_char_p,
        ct.c_int,
        ct.c_int,
        ct.c_int,
        ct.POINTER(rmtauth),
        ct.c_char_p)(
        ("pcap_open", dll), (
        (1, "source"),
        (1, "snaplen"),
        (1, "flags"),
        (1, "read_timeout"),
        (1, "auth"),
        (1, "errbuf"),))
except: pass

try:  # PCAP_AVAILABLE_1_9_REMOTE
    # ifdef ENABLE_REMOTE
    createsrcstr = CFUNC(ct.c_int,
        ct.c_char_p,
        ct.c_int,
        ct.c_char_p,
        ct.c_char_p,
        ct.c_char_p,
        ct.c_char_p)(
        ("pcap_createsrcstr", dll), (
        (1, "source"),
        (1, "type"),
        (1, "host"),
        (1, "port"),
        (1, "name"),
        (1, "errbuf"),))
except: pass

try:  # PCAP_AVAILABLE_1_9_REMOTE
    # ifdef ENABLE_REMOTE
    parsesrcstr = CFUNC(ct.c_int,
        ct.c_char_p,
        ct.POINTER(ct.c_int),
        ct.c_char_p,
        ct.c_char_p,
        ct.c_char_p,
        ct.c_char_p)(
        ("pcap_parsesrcstr", dll), (
        (1, "source"),
        (1, "type"),
        (1, "host"),
        (1, "port"),
        (1, "name"),
        (1, "errbuf"),))
except: pass

# This routine can scan a directory for savefiles, list local capture
# devices, or list capture devices on a remote machine running an RPCAP
# server.
#
# For scanning for savefiles, it can be used on both UN*X systems and
# Windows systems; for each directory entry it sees, it tries to open
# the file as a savefile using pcap.open_offline(), and only includes
# it in the list of files if the open succeeds, so it filters out
# files for which the user doesn't have read permission, as well as
# files that aren't valid savefiles readable by libpcap.
#
# For listing local capture devices, it's just a wrapper around
# pcap.findalldevs(); code using pcap.findalldevs() will work on more
# platforms than code using pcap.findalldevs_ex().
#
# For listing remote capture devices, pcap.findalldevs_ex() is currently
# the only API available.
#
try:  # PCAP_AVAILABLE_1_9_REMOTE
    # ifdef ENABLE_REMOTE
    findalldevs_ex = CFUNC(ct.c_int,
        ct.c_char_p,
        ct.POINTER(rmtauth),
        ct.POINTER(ct.POINTER(pcap_if_t)),
        ct.c_char_p)(
        ("pcap_findalldevs_ex", dll), (
        (1, "source"),
        (1, "auth"),
        (1, "alldevs"),
        (1, "errbuf"),))
except: pass

# New functions.

try:  # PCAP_AVAILABLE_1_9_REMOTE
    # ifdef ENABLE_REMOTE
    setsampling = CFUNC(ct.POINTER(samp),
        ct.POINTER(pcap_t))(
        ("pcap_setsampling", dll), (
        (1, "pcap"),))
except: pass

try:  # PCAP_AVAILABLE_1_9_REMOTE
    # ifdef ENABLE_REMOTE
    remoteact_accept = CFUNC(PCAP_SOCKET,
        ct.c_char_p,
        ct.c_char_p,
        ct.c_char_p,
        ct.c_char_p,
        ct.POINTER(rmtauth),
        ct.c_char_p)(
        ("pcap_remoteact_accept", dll), (
        (1, "address"),
        (1, "port"),
        (1, "hostlist"),
        (1, "connectinghost"),
        (1, "auth"),
        (1, "errbuf"),))
except: pass

try:  # PCAP_AVAILABLE_1_10_REMOTE
    # ifdef ENABLE_REMOTE
    remoteact_accept_ex = CFUNC(PCAP_SOCKET,
        ct.c_char_p,
        ct.c_char_p,
        ct.c_char_p,
        ct.c_char_p,
        ct.POINTER(rmtauth),
        ct.c_int,
        ct.c_char_p)(
        ("pcap_remoteact_accept_ex", dll), (
        (1, "address"),
        (1, "port"),
        (1, "hostlist"),
        (1, "connectinghost"),
        (1, "auth"),
        (1, "uses_ssl"),
        (1, "errbuf"),))
except: pass

try:  # PCAP_AVAILABLE_1_9_REMOTE
    # ifdef ENABLE_REMOTE
    remoteact_list = CFUNC(ct.c_int,
        ct.c_char_p,
        ct.c_char,
        ct.c_int,
        ct.c_char_p)(
        ("pcap_remoteact_list", dll), (
        (1, "hostlist"),
        (1, "sep"),
        (1, "size"),
        (1, "errbuf"),))
except: pass

try:  # PCAP_AVAILABLE_1_9_REMOTE
    # ifdef ENABLE_REMOTE
    remoteact_close = CFUNC(ct.c_int,
        ct.c_char_p,
        ct.c_char_p)(
        ("pcap_remoteact_close", dll), (
        (1, "host"),
        (1, "errbuf"),))
except: pass

try:  # PCAP_AVAILABLE_1_9_REMOTE
    # ifdef ENABLE_REMOTE
    remoteact_cleanup = CFUNC(None)(
        ("pcap_remoteact_cleanup", dll),)
except: pass

option_name = ct.c_int
(   # never renumber this
    PON_TSTAMP_PRECISION1,  # int
    PON_IO_READ_PLUGIN,     # char *
    PON_IO_WRITE_PLUGIN,    # char *
) = (1, 2, 3)

class options(ct.Structure): pass

try:  # PCAP_AVAILABLE_1_11
    alloc_option = CFUNC(ct.POINTER(options))(
        ("pcap_alloc_option", dll),)
except: pass

try:  # PCAP_AVAILABLE_1_11
    free_option = CFUNC(None,
        ct.POINTER(options))(
        ("pcap_free_option", dll), (
        (1, "po"),))
except: pass

try:  # PCAP_AVAILABLE_1_11
    set_option_string = CFUNC(ct.c_int,
        ct.POINTER(options),
        option_name,
        ct.c_char_p)(
        ("pcap_set_option_string", dll), (
        (1, "po"),
        (1, "pon"),
        (1, "value"),))
except: pass

try:  # PCAP_AVAILABLE_1_11
    set_option_int = CFUNC(ct.c_int,
        ct.POINTER(options),
        option_name,
        ct.c_int)(
        ("pcap_set_option_int", dll), (
        (1, "po"),
        (1, "pon"),
        (1, "value"),))
except: pass

try:  # PCAP_AVAILABLE_1_11
    get_option_string = CFUNC(ct.c_char_p,
        ct.POINTER(options),
        option_name)(
        ("pcap_get_option_string", dll), (
        (1, "po"),
        (1, "pon"),))
except: pass

try:  # PCAP_AVAILABLE_1_11
    get_option_int = CFUNC(ct.c_int,
        ct.POINTER(options),
        option_name)(
        ("pcap_get_option_int", dll), (
        (1, "po"),
        (1, "pon"),))
except: pass

# eof
