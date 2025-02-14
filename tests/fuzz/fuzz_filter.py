#!/usr/bin/env python

# Copyright (c) 2016 Adam Karpierz
# SPDX-License-Identifier: BSD-3-Clause

import sys
import ctypes as ct

import libpcap as pcap
from _utils import *  # noqa


def LLVMFuzzerTestOneInput(data: bytes) -> int:

    bpf = pcap.bpf_program()

    # we need at least 1 byte for linktype
    if len(data) < 1:
        return 0

    # initialize structure snaplen = 65535
    pkts = pcap.open_dead(data[-1], 0xFFFF)
    if not pkts:
        print("pcap_open_dead failed")
        return 0

    filter = ct.c_char_p(data[:-1])

    if pcap.compile(pkts, ct.byref(bpf), filter, 1, pcap.PCAP_NETMASK_UNKNOWN) == 0:
        if pcap.setfilter(pkts, ct.byref(bpf)) < 0:
            pcap.perror(pkts, b"pcap.setfilter")
        pcap.close(pkts)
        pcap.freecode(ct.byref(bpf))
    else:
        pcap.close(pkts)

    return 0


if __name__.rpartition(".")[-1] == "__main__":
    import onefile
    onefile.fuzz_openFile          = None  # do nothing
    onefile.LLVMFuzzerTestOneInput = LLVMFuzzerTestOneInput
    from onefile import main
    sys.exit(main())
