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
    bpf = pcap.bpf_program()

    if len(data) < 1:
        return 0

    filter_offs = 1
    filter_size = data[0]
    if filter_size == 0 or len(data) < filter_offs + filter_size:
        return 0

    # generate temporary file name
    try:
        tmp_file = tempfile.NamedTemporaryFile(prefix="libpcap_fuzz_both.",
                                               delete_on_close=False)
    except Exception:
        return 0
    with tmp_file:
        tmp_file.file.close()
        filename = tmp_file.name

        # rewrite buffer to a file as libpcap does not have buffer inputs
        if bufferToFile(filename, data[filter_offs + filter_size:]) < 0:
            return 0

        # initialize structure
        pkts = pcap.open_offline(filename.encode("utf-8"), errbuf)
        if not pkts:
            print("Couldn't open pcap file {}".format(ebuf2str(errbuf)), file=outfile)
            return 0

        filter = ct.c_char_p(data[filter_offs:filter_offs + filter_size])

        if pcap.compile(pkts, ct.byref(bpf), filter, 1, pcap.PCAP_NETMASK_UNKNOWN) == 0:
            # loop over packets
            headerp = ct.POINTER(pcap_pkthdr)()
            pkt = ct.POINTER(ct.c_ubyte)()
            r: int = pcap.next_ex(pkts, ct.byref(headerp), ct.byref(pkt))
            while r > 0:
                header = headerp.contents
                # checks filter
                print("packet length={}/{} filter={}".format(header.caplen, header.len,
                      pcap.offline_filter(ct.byref(bpf), headerp, pkt)), file=outfile)
                r = pcap.next_ex(pkts, ct.byref(headerp), ct.byref(pkt))

            # close structure
            pcap.close(pkts)
            pcap.freecode(ct.byref(bpf))
        else:
            pcap.close(pkts)

    return 0


if __name__.rpartition(".")[-1] == "__main__":
    import onefile
    onefile.fuzz_openFile          = fuzz_openFile
    onefile.LLVMFuzzerTestOneInput = LLVMFuzzerTestOneInput
    from onefile import main
    sys.exit(main())
