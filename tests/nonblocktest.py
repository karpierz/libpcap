# Copyright (c) 2016 Adam Karpierz
# SPDX-License-Identifier: BSD-3-Clause

# Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 2000
#    The Regents of the University of California.  All rights reserved.
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
import getopt
import ctypes as ct

import libpcap as pcap
from libpcap._platform import is_windows
from pcaptestutils import *  # noqa

pd = ct.POINTER(pcap.pcap_t)()


@pcap.pcap_handler
def breakme(arg, hdr, pkt):
    global pd
    warning("using pcap.breakloop()")
    pcap.breakloop(pd)


# Tests for pcap.set_nonblock / pcap.get_nonblock:
# - idempotency
# - set/get are symmetric
# - get returns the same before/after activate
# - pcap.breakloop works after setting nonblock on and then off
#
# Really this is meant to
# be run manually under strace, to check for extra
# calls to eventfd or close.

def main(argv=sys.argv[1:]):

    global program_name
    program_name = os.path.basename(sys.argv[0])

    global pd

    try:
        opts, args = getopt.getopt(argv, "i")
    except getopt.GetoptError:
        usage()

    device = None
    for opt, optarg in opts:
        if opt == '-i':
            device = optarg.encode("utf-8")
        else:
            usage()

    ebuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)

    if device is None:
        devlist = ct.POINTER(pcap.pcap_if_t)()
        if pcap.findalldevs(ct.byref(devlist), ebuf) == -1:
            error("{}", ebuf2str(ebuf))
        if not devlist:
            error("no interfaces available for capture")
        device = devlist[0].name
        warning("listening on {}", device.decode("utf-8"))
        pcap.freealldevs(devlist)

    ebuf[0] = b"\0"

    pd = pcap.create(device, ebuf)
    if not pd:
        error("{}", ebuf2str(ebuf))
    elif ebuf.value:
        warning("{}", ebuf2str(ebuf))
    # set nonblock before activate
    if pcap.setnonblock(pd, 1, ebuf) < 0:
        error("pcap.setnonblock failed: {}", ebuf2str(ebuf))
    # getnonblock just returns "not activated yet"
    ret = pcap.getnonblock(pd, ebuf)
    if ret != pcap.PCAP_ERROR_NOT_ACTIVATED:
        error("pcap.getnonblock unexpectedly succeeded")
    status = pcap.activate(pd)
    if status < 0:
        error("pcap.activate failed")
    ret = pcap.getnonblock(pd, ebuf)
    if ret != 1:
        error("pcap.getnonblock did not return nonblocking")

    # Set nonblock multiple times, ensure with strace that it's a noop
    for i in range(10):
        if pcap.setnonblock(pd, 1, ebuf) < 0:
            error("pcap.setnonblock failed: {}", ebuf2str(ebuf))
        ret = pcap.getnonblock(pd, ebuf)
        if ret != 1:
            error("pcap.getnonblock did not return nonblocking")
    # Set block multiple times, ensure with strace that it's a noop
    for i in range(10):
        if pcap.setnonblock(pd, 0, ebuf) < 0:
            error("pcap.setnonblock failed: {}", ebuf2str(ebuf))
        ret = pcap.getnonblock(pd, ebuf)
        if ret != 0:
            error("pcap.getnonblock did not return blocking")

    # Now pcap.loop forever, with a callback that
    # uses pcap.breakloop to get out of forever
    status = pcap.loop(pd, -1, breakme, None)
    if status != pcap.PCAP_ERROR_BREAK:
        if status >= 0:
            error("pcap.breakloop didn't cause a break")
        error("pcap.loop failed: {}", geterr2str(pd))

    # Now test that pcap.setnonblock fails if we can't open the
    # eventfd.
    if pcap.setnonblock(pd, 1, ebuf) < 0:
        error("pcap.setnonblock failed: {}", ebuf2str(ebuf))
    while True:
        try:
            ret = os.open(os.devnull,
                          (os.O_RDONLY | os.O_BINARY) if is_windows else os.O_RDONLY)
        except Exception:
            break
        if ret < 0:
            break
    ret = pcap.setnonblock(pd, 0, ebuf)
    if ret == 0:
        error("pcap.setnonblock succeeded even though file table is full")
    else:
        warning("pcap.setnonblock failed as expected: {}", ebuf2str(ebuf))


def usage():
    print("Usage: {} [ -i interface ]".format(program_name), file=sys.stderr)
    sys.exit(1)


if __name__.rpartition(".")[-1] == "__main__":
    sys.exit(main())
