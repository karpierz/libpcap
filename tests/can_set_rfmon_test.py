#!/usr/bin/env python

# Copyright (c) 2016-2019, Adam Karpierz
# Licensed under the BSD license
# http://opensource.org/licenses/BSD-3-Clause

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

from __future__ import absolute_import, division, print_function

import sys
import os
import ctypes as ct

import libpcap as pcap

#ifndef lint
copyright = "@(#) Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, "\
            "1995, 1996, 1997, 2000\n"\
            "The Regents of the University of California.  "\
            "All rights reserved.\n"
#endif

try:
    statustostr = pcap.statustostr
except AttributeError:
    statustostr = lambda status: str(status).encode("utf-8")


def main(argv):

    global program_name
    program_name = os.path.basename(argv[0])

    if len(argv) != 2:
        print("Usage: {} <device>".format(program_name), file=sys.stderr)
        return 2

    device = argv[1]

    ebuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)
    pd = pcap.create(device.encode("utf-8"), ebuf)
    if not pd:
        error("{!s}", ebuf.value.decode("utf-8", "ignore"))

    try:
        status = pcap.can_set_rfmon(pd)
    except AttributeError:
        error("pcap.can_set_rfmon is not available on this platform")
    if status < 0:
        if status == pcap.PCAP_ERROR:
            error("{}: pcap.can_set_rfmon failed: {!s}",
                  device, pcap.geterr(pd).decode("utf-8", "ignore"))
        else:
            error("{}: pcap.can_set_rfmon failed: {!s}",
                  device, statustostr(status).decode("utf-8", "ignore"))

    print("{}: Monitor mode {} be set".format(
          device, "can" if status else "cannot"))

    return 0


def error(fmt, *args):

    global program_name
    print("{}: ".format(program_name), end="", file=sys.stderr)
    print(fmt.format(*args), end="", file=sys.stderr)
    if fmt and fmt[-1] != '\n':
        print(file=sys.stderr)
    sys.exit(1)


sys.exit(main(sys.argv) or 0)
