#!/usr/bin/env python

# Copyright (c) 2016 Adam Karpierz
# SPDX-License-Identifier: BSD-3-Clause

# Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 2000
#  The Regents of the University of California.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that: (1) source code distributions
# retain the above copyright notice and this paragraph in its entirety, (2)
# distributions including binary code include the above copyright notice and
# this paragraph in its entirety in the documentation or other materials
# provided with the distribution, and (3) all advertising materials mentioning
# features or use of this software display the following acknowledgement:
# ``This product includes software developed by the University of California,
# Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
# the University nor the names of its contributors may be used to endorse
# or promote products derived from this software without specific prior
# written permission.
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

import sys
import os
import ctypes as ct

import libpcap as pcap
from pcaptestutils import *  # noqa

#ifndef lint
copyright = "@(#) Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, "\
            "1995, 1996, 1997, 2000\n"\
            "The Regents of the University of California.  "\
            "All rights reserved.\n"
#endif


def main(argv=sys.argv[1:]):

    global program_name
    program_name = os.path.basename(sys.argv[0])

    if len(argv) != 1:
        error("expecting exactly one command-line argument with the interface name")

    ifname = argv[0]

    ebuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)

    pd = pcap.open_live(ifname.encode("utf-8"), 65535, 0, 1000, ebuf)
    if not pd:
        error("pcap_open_live() failed: {}", ebuf2str(ebuf))

    status = pcap.activate(pd)
    if status != pcap.PCAP_ERROR_ACTIVATED:
        if status == 0:
            error("pcap.activate() of opened pcap_t succeeded")
        elif status == pcap.PCAP_ERROR:
            error("pcap.activate() of opened pcap_t failed with {}, "
                  "not PCAP_ERROR_ACTIVATED", geterr2str(pd))
        else:
            error("pcap.activate() of opened pcap_t failed with {}, "
                  "not PCAP_ERROR_ACTIVATED", status2str(status))

    return 0


if __name__.rpartition(".")[-1] == "__main__":
    sys.exit(main())
