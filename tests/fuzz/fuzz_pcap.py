#!/usr/bin/env python

# Copyright (c) 2016 Adam Karpierz
# SPDX-License-Identifier: BSD-3-Clause

import sys
import os
import tempfile
import ctypes as ct

import libpcap as pcap
from _utils import *  # noqa


outfile = None

def fuzz_openFile(filename: str):
    global outfile

    if outfile is not None:
        outfile.close()
    outfile = open(filename, "wt")


def bufferToFile(filename: str, data: bytes) -> int:
    try:
        os.remove(filename)
    except FileNotFoundError:
        pass
    except Exception as exc:
        print("failed remove, errno={}".format(exc.errno))
        return -1

    try:
        file = open(filename, "wb")
    except Exception as exc:
        print("failed open, errno={}".format(exc.errno))
        return -2
    with file:
        try:
            nwritten = file.write(data)
        except Exception as exc:
            return -3
        if nwritten != len(data):
            return -3
    return 0


def LLVMFuzzerTestOneInput(data: bytes) -> int:

    global outfile

    # initialize output file
    if outfile is None:
        try:
            outfile = open(os.devnull, "wt")
        except Exception:
            return 0

    errbuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)
    stats = pcap.stat()

    # generate temporary file name
    try:
        tmp_file = tempfile.NamedTemporaryFile(prefix="libpcap_fuzz_pcap.",
                                               delete_on_close=False)
    except Exception:
        return 0
    with tmp_file:
        tmp_file.file.close()
        filename = tmp_file.name

        # rewrite buffer to a file as libpcap does not have buffer inputs
        if bufferToFile(filename, data) < 0:
            return 0

        # initialize structure
        pkts = pcap.open_offline(filename.encode("utf-8"), errbuf)
        if not pkts:
            print("Couldn't open pcap file {}".format(ebuf2str(errbuf)), file=outfile)
            return 0

        # loop over packets
        headerp = ct.POINTER(pcap_pkthdr)()
        pkt = ct.POINTER(ct.c_ubyte)()
        r: int = pcap.next_ex(pkts, ct.byref(headerp), ct.byref(pkt))
        while r > 0:
            header = headerp.contents
            # TODO pcap.offline_filter
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
