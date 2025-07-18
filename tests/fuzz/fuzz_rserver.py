#!/usr/bin/env python

# Copyright (c) 2016 Adam Karpierz
# SPDX-License-Identifier: BSD-3-Clause

import sys
import os
import enum
import ctypes as ct
import socket

import libpcap as pcap
# int daemon_serviceloop(pcap.PCAP_SOCKET sockctrl, int isactive, char *passiveClients,
#                        int nullAuthAllowed, char *data_port, int uses_ssl);
# from !!! ??? import daemon_serviceloop
from _utils import sock_initfuzz
from _utils import *  # noqa


class log_priority(enum.IntEnum):
    LOGPRIO_DEBUG   = 0
    LOGPRIO_INFO    = 1
    LOGPRIO_WARNING = 2
    LOGPRIO_ERROR   = 3

def rpcapd_log(priority: log_priority, message: str, *args):
    global outfile
    print("rpcapd[%d]:%s" % (priority, message % args), file=outfile)


outfile = None

def fuzz_openFile(filename: str):
    global outfile

    if outfile is not None:
        outfile.close()
    outfile = open(filename, "wt")


def LLVMFuzzerTestOneInput(data: bytes) -> int:

    global outfile

    # initialization
    if outfile is None:
        fuzz_openFile(os.devnull)

    sock_initfuzz(ct.cast(ct.c_char_p(data), ct.POINTER(ct.c_uint8)), len(data))
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    except OSError as exc:
        os.abort()

    # dummy socket, active, null auth allowed, no ssl
    daemon_serviceloop(sock, 1, libc.malloc(0), 1, b"\0", 0)

    return 0


if __name__.rpartition(".")[-1] == "__main__":
    import onefile
    onefile.fuzz_openFile          = fuzz_openFile
    onefile.LLVMFuzzerTestOneInput = LLVMFuzzerTestOneInput
    from onefile import main
    # ../../rpcapd/daemon.c
    sys.exit(main())
