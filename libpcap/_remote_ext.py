# Copyright (c) 2016-2017, Adam Karpierz
# Licensed under the BSD license
# https://opensource.org/licenses/BSD-3-Clause

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

# file: _remote_ext.py
#
# Includes most of the public stuff that is needed for the remote capture

from __future__ import absolute_import

import ctypes as ct

from ._platform import is_windows, defined
from ._platform import CFUNC
from ._dll      import dll
from ._pcap     import pcap_t, pcap_if_t

# The goal of this file it to include most of the new definitions that should
# be placed into the pcap.h file.
#
# It includes all new definitions (structures and functions like pcap.open().
# Some of the functions are not really a remote feature, but, right now,
# they are placed here.

# We have to define the SOCKET here, although it has been defined in
# sockutils.h
# This is to avoid the distribution of the 'sockutils.h' file around
# (for example in the WinPcap developer's pack)
if is_windows:
    SOCKET = ct.c_uint
else:
    SOCKET = ct.c_int

# Defines the maximum buffer size in which address, port, interface names are
# kept.
#
# In case the adapter name or such is larger than this value, it is truncated.
# This is not used by the user; however it must be aware that an
# hostname / interface name longer than this value will be truncated.

PCAP_BUF_SIZE = 1024

## Remote source IDs

# Internal representation of the type of source in use (file,
# remote/local interface).
#
# This indicates a file, i.e. the user want to open a capture from a
# local file.

PCAP_SRC_FILE = 2

# Internal representation of the type of source in use (file,
# remote/local interface).
#
# This indicates a local interface, i.e. the user want to open a capture from
# a local interface. This does not involve the RPCAP protocol.

PCAP_SRC_IFLOCAL = 3

# Internal representation of the type of source in use (file,
# remote/local interface).
#
# This indicates a remote interface, i.e. the user want to open a capture from
# an interface on a remote host. This does involve the RPCAP protocol.

PCAP_SRC_IFREMOTE = 4

# Remote source string
#
# The formats allowed by the pcap.open() are the following:
# - file://path_and_filename [opens a local file]
# - rpcap://devicename [opens the selected device devices available on the
#   local host, without using the RPCAP protocol]
# - rpcap://host/devicename [opens the selected device available on a remote
#   host]
# - rpcap://host:port/devicename [opens the selected device available on a
#   remote host, using a non-standard port for RPCAP]
# - adaptername [to open a local adapter; kept for compability, but it is
#   strongly discouraged]
# - (NULL) [to open the first local adapter; kept for compability, but it is
#   strongly discouraged]
#
# The formats allowed by the pcap.findalldevs_ex() are the following:
# - file://folder/ [lists all the files in the given folder]
# - rpcap:// [lists all local adapters]
# - rpcap://host:port/ [lists the devices available on a remote host]
#
# Referring to the 'host' and 'port' paramters, they can be either numeric or
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
# - rpcap://10.11.12.13/devicename [IPv4 numeric, no port number]
# - rpcap://10.11.12.13:1234/devicename [IPv4 numeric, with port number]
# - rpcap://[10.11.12.13]:1234/devicename [IPv4 numeric with IPv6 format, with
#                                          port number]
# - rpcap://[1:2:3::4]/devicename [IPv6 numeric, no port number]
# - rpcap://[1:2:3::4]:1234/devicename [IPv6 numeric, with port number]
# - rpcap://[1:2:3::4]:http/devicename [IPv6 numeric, with literal port number]

# String that will be used to determine the type of source in use (file,
# remote/local interface).
#
# This string will be prepended to the interface name in order to create
# a string that contains all the information required to open the source.
#
# This string indicates that the user wants to open a capture from a local
# file.

PCAP_SRC_FILE_STRING = "file://"

# String that will be used to determine the type of source in use (file,
# remote/local interface).
#
# This string will be prepended to the interface name in order to create
# a string that contains all the information required to open the source.
#
# This string indicates that the user wants to open a capture from a network
# interface.
# This string does not necessarily involve the use of the RPCAP protocol.
# If the interface required resides on the local host, the RPCAP protocol
# is not involved and the local functions are used.

PCAP_SRC_IF_STRING = "rpcap://"

## Remote open flags

# Defines if the adapter has to go in promiscuous mode.
#
# It is '1' if you have to open the adapter in promiscuous mode, '0' otherwise.
# Note that even if this parameter is false, the interface could well be in
# promiscuous mode for some other reason (for example because another capture
# process with promiscuous mode enabled is currently using that interface).
# On on Linux systems with 2.2 or later kernels (that have the "any" device),
# this flag does not work on the "any" device; if an argument of "any" is
# supplied, the 'promisc' flag is ignored.

PCAP_OPENFLAG_PROMISCUOUS = 1

# Defines if the data trasfer (in case of a remote
# capture) has to be done with UDP protocol.
#
# If it is '1' if you want a UDP data connection, '0' if you want
# a TCP data connection; control connection is always TCP-based.
# A UDP connection is much lighter, but it does not guarantee that all
# the captured packets arrive to the client workstation. Moreover,
# it could be harmful in case of network congestion.
# This flag is meaningless if the source is not a remote interface.
# In that case, it is simply ignored.

PCAP_OPENFLAG_DATATX_UDP = 2

# Defines if the remote probe will capture its own generated traffic.
#
# In case the remote probe uses the same interface to capture traffic and to
# send data back to the caller, the captured traffic includes the RPCAP traffic
# as well. If this flag is turned on, the RPCAP traffic is excluded from the
# capture, so that the trace returned back to the collector is does not include
# this traffic.

PCAP_OPENFLAG_NOCAPTURE_RPCAP = 4

# Defines if the local adapter will capture its own generated traffic.
#
# This flag tells the underlying capture driver to drop the packets that were
# sent by itself. This is usefult when building applications like bridges,
# that should ignore the traffic they just sent.

PCAP_OPENFLAG_NOCAPTURE_LOCAL = 8

# This flag configures the adapter for maximum responsiveness.
#
# In presence of a large value for nbytes, WinPcap waits for the arrival of
# several packets before copying the data to the user. This guarantees a low
# number of system calls, i.e. lower processor usage, i.e. better performance,
# which is good for applications like sniffers. If the user sets the
# PCAP_OPENFLAG_MAX_RESPONSIVENESS flag, the capture driver will copy
# the packets as soon as the application is ready to receive them.
# This is suggested for real time applications (like, for example, a bridge)
# that need the best responsiveness.

PCAP_OPENFLAG_MAX_RESPONSIVENESS = 16

## Sampling Methods Section

# No sampling has to be done on the current capture.
#
# In this case, no sampling algorithms are applied to the current capture.

PCAP_SAMP_NOSAMP = 0

# It defines that only 1 out of N packets must be returned to the user.
#
# In this case, the 'value' field of the 'pcap.samp' structure indicates the
# number of packets (minus 1) that must be discarded before one packet got
# accepted. In other words, if 'value = 10', the first packet is returned
# to the caller, while the following 9 are discarded.

PCAP_SAMP_1_EVERY_N = 1

# It defines that we have to return 1 packet every N milliseconds.
#
# In this case, the 'value' field of the 'pcap.samp' structure indicates the
# 'waiting time' in milliseconds before one packet got accepted.
# In other words, if 'value = 10', the first packet is returned to the caller;
# the next returned one will be the first packet that arrives when 10ms have
# elapsed.

PCAP_SAMP_FIRST_AFTER_N_MS = 2

# Remote Authentication Methods Section

# It defines the NULL authentication.
#
# This value has to be used within the 'type' member of the pcap.rmtauth
# structure. The 'NULL' authentication has to be equal to 'zero', so that old
# applications can just put every field of struct pcap.rmtauth to zero, and it
# does work.

RPCAP_RMTAUTH_NULL = 0

# It defines the username/password authentication.
#
# With this type of authentication, the RPCAP protocol will use the username/
# password provided to authenticate the user on the remote machine. If the
# authentication is successful (and the user has the right to open network
# devices) the RPCAP connection will continue; otherwise it will be dropped.
#
# This value has to be used within the 'type' member of the pcap.rmtauth
# structure.

RPCAP_RMTAUTH_PWD = 1

## Structures

# This structure keeps the information needed to autheticate
# the user on a remote machine.
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

# This structure defines the information related to sampling.
#
# In case the sampling is requested, the capturing device should read
# only a subset of the packets coming from the source. The returned packets
# depend on the sampling parameters.
#
# Warning:
# The sampling process is applied <strong>after</strong> the filtering process.
# In other words, packets are filtered first, then the sampling process selects
# a subset of the 'filtered' packets and it returns them to the caller.

class samp(ct.Structure):
    _fields_ = [

    # Method used for sampling. Currently, the supported methods are listed
    # in the Sampling Methods Section.

    ("method", ct.c_int),

    # This value depends on the sampling method defined. For its meaning,
    # please check at the Sampling Methods Section.

    ("value", ct.c_int),
]

# Maximum lenght of an host name (needed for the RPCAP active mode)

RPCAP_HOSTLIST_SIZE = 1024

#
# Exported functions
#

# New WinPcap functions
#
# This section lists the new functions that are able to help considerably
# in writing WinPcap programs because of their easiness of use.

open          = CFUNC(ct.POINTER(pcap_t),
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

createsrcstr  = CFUNC(ct.c_int,
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

parsesrcstr   = CFUNC(ct.c_int,
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

setsampling   = CFUNC(ct.POINTER(samp),
                      ct.POINTER(pcap_t))(
                      ("pcap_setsampling", dll), (
                      (1, "pcap"),))

# Remote Capture functions

remoteact_accept = CFUNC(SOCKET,
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

remoteact_close = CFUNC(ct.c_int,
                      ct.c_char_p,
                      ct.c_char_p)(
                      ("pcap_remoteact_close", dll), (
                      (1, "host"),
                      (1, "errbuf"),))

remoteact_cleanup = CFUNC(None)(
                      ("pcap_remoteact_cleanup", dll),)

# eof
