#!/usr/bin/env python

# Copyright (c) 2016 Adam Karpierz
# SPDX-License-Identifier: BSD-3-Clause

import sys
import os
import ctypes as ct

import libpcap as pcap
from _utils import sock_initfuzz
from _utils import *  # noqa


outfile = None
auth = pcap.rmtauth()


def fuzz_openFile(filename: str):
    global outfile
    global auth

    if outfile is not None:
        outfile.close()
    outfile = open(filename, "wt")

    auth.type = pcap.RPCAP_RMTAUTH_PWD
    auth.username = b"user"
    auth.password = b"pass"


def LLVMFuzzerTestOneInput(data: bytes) -> int:

    global outfile
    global auth

    errbuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)
    stats  = pcap.stat()

    # initialization
    if outfile is None:
        fuzz_openFile(os.devnull)

    sock_initfuzz(ct.cast(ct.c_char_p(data), ct.POINTER(ct.c_uint8)), len(data))
    # initialize structure
    pkts = pcap.open(b"rpcap://127.0.0.1/fuzz.pcap", 0, 0, 1000, ct.byref(auth), errbuf)
    if not pkts:
        print("Couldn't open pcap file {}".format(ebuf2str(errbuf)), file=outfile)
        return 0

    # loop over packets
    headerp = ct.POINTER(pcap.pkthdr)()
    pkt = ct.POINTER(ct.c_ubyte)()
    r = pcap.next_ex(pkts, ct.byref(headerp), ct.byref(pkt))
    while r > 0:
        header = headerp.contents
        print("packet length={}/{}".format(header.caplen, header.len), file=outfile)
        r = pcap.next_ex(pkts, ct.byref(headerp), ct.byref(pkt))
    if pcap.stats(pkts, ct,byref(stats)) == 0:
        print("number of packets={}".format(stats.ps_recv), file=outfile)

    # close structure
    pcap.close(pkts)

    return 0


if __name__.rpartition(".")[-1] == "__main__":
    import onefile
    onefile.fuzz_openFile          = fuzz_openFile
    onefile.LLVMFuzzerTestOneInput = LLVMFuzzerTestOneInput
    from onefile import main
    sys.exit(main())
