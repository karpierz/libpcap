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
import getopt
import ctypes as ct

import libpcap as pcap
from libpcap._platform import is_windows
from pcaptestutils import *  # noqa

#ifndef lint
copyright = "@(#) Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, "\
            "1995, 1996, 1997, 2000\n"\
            "The Regents of the University of California.  "\
            "All rights reserved.\n"
#endif

pd = ct.POINTER(pcap.pcap_t)()

if not is_windows:
    breaksigint = False

    #static void sigint_handler(int signum _U_)
    def sigint_handler(signum):
        global pd
        global breaksigint
        if breaksigint:
            pcap.breakloop(pd)


def main(argv=sys.argv[1:]):

    global program_name
    program_name = os.path.basename(sys.argv[0])

    global pd
    global breaksigint

    try:
        opts, args = getopt.getopt(argv, "i:mnt:" if is_windows else "bi:mnrst:")
    except getopt.GetoptError:
        usage()

    device = None
    immediate = False
    nonblock = 0
    if not is_windows:
        sigrestart  = False
        catchsigint = False
    timeout = 1000
    for opt, optarg in opts:
        if not is_windows and opt == '-b':
            breaksigint = True
        elif opt == '-i':
            device = optarg.encode("utf-8")
        elif opt == '-m':
            immediate = True
        elif opt == '-n':
            nonblock = 1
        elif not is_windows and opt == '-r':
            sigrestart = True
        elif not is_windows and opt == '-s':
            catchsigint = True
        elif opt == '-t':
            try:
                timeout = int(optarg)
            except Exception:
                error('Timeout value "{}" is not a number', optarg)
            if timeout < 0:
                error("Timeout value {:d} is negative", timeout)
            if timeout > INT_MAX:
                error("Timeout value {:d} is too large (> {:d})",
                      timeout, INT_MAX)
        else:
            usage()

    expression = args

    ebuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)

    if device is None:
        devlist = ct.POINTER(pcap.pcap_if_t)()
        if pcap.findalldevs(ct.byref(devlist), ebuf) == -1:
            error("{}", ebuf2str(ebuf))
        if not devlist:
            error("no interfaces available for capture")
        device = devlist[0].name
        pcap.freealldevs(devlist)

    ebuf[0] = b"\0"

    if not is_windows:
        # If we were told to catch SIGINT, do so.
        if catchsigint:
            action = sigaction()
            action.sa_handler = sigint_handler
            sigemptyset(ct.byref(action.sa_mask))
            # Should SIGINT interrupt, or restart, system calls?
            action.sa_flags = SA_RESTART if sigrestart else 0
            if sigaction(SIGINT, ct.byref(action), NULL) == -1:
                error("Can't catch SIGINT: {}", strerror(errno))

    pd = pcap.create(device, ebuf)
    if not pd:
        error("{}", ebuf2str(ebuf))

    status = pcap.set_snaplen(pd, 65535)
    if status != 0:
        error("{}: pcap.set_snaplen failed: {}",
              device2str(device), status2str(status));
    if immediate:
        try:
            status = pcap.set_immediate_mode(pd, 1)
        except AttributeError:
            error("pcap.set_immediate_mode is not available on this platform")
        if status != 0:
            error("{}: pcap.set_immediate_mode failed: {}",
                  device2str(device), status2str(status))
    status = pcap.set_timeout(pd, timeout)
    if status != 0:
        error("{}: pcap.set_timeout failed: {}",
              device2str(device), status2str(status))

    status = pcap.activate(pd)
    if status < 0:
        # pcap.activate() failed.
        error("{}: {}\n({})",
              device2str(device), status2str(status), geterr2str(pd))
    elif status > 0:
        # pcap.activate() succeeded, but it's warning us
        # of a problem it had.
        warning("{}: {}\n({})",
                device2str(device), status2str(status), geterr2str(pd))

    localnet = pcap.bpf_u_int32()
    netmask  = pcap.bpf_u_int32()
    if pcap.lookupnet(device, ct.byref(localnet), ct.byref(netmask), ebuf) < 0:
        localnet = pcap.bpf_u_int32(0)
        netmask  = pcap.bpf_u_int32(0)
        warning("{}", ebuf2str(ebuf))

    fcode = pcap.bpf_program()
    cmdbuf = " ".join(expression).encode("utf-8")
    if pcap.compile(pd, ct.byref(fcode), cmdbuf, 1, netmask) < 0:
        error("{}", geterr2str(pd))

    if pcap.setfilter(pd, ct.byref(fcode)) < 0:
        error("{}", geterr2str(pd))
    if pcap.setnonblock(pd, nonblock, ebuf) == -1:
        error("pcap.setnonblock failed: {}", ebuf2str(ebuf))

    print("Listening on {}".format(device2str(device)))

    while True:
        packet_count = ct.c_int(0)
        status = pcap.dispatch(pd, -1, countme,
                 ct.cast(ct.pointer(packet_count), ct.POINTER(ct.c_ubyte)))
        if status < 0:
            break
        if status != 0:
            print("{:d} packets seen, {:d} packets counted after "
                  "pcap.dispatch returns".format(status, packet_count.value))
            ps = pcap.stat()
            if pcap.stats(pd, ct.byref(ps)) < 0:
                print("pcap.stats: {}".format(geterr2str(pd)), file=sys.stderr)
            else:
                print("{:d} ps_recv, {:d} ps_drop, {:d} ps_ifdrop".format(
                      ps.ps_recv, ps.ps_drop, ps.ps_ifdrop))

    if status == pcap.PCAP_ERROR_BREAK:
        # We got interrupted, so perhaps we didn't manage to finish a
        # line we were printing. Print an extra newline, just in case.
        print()
        print("Broken out of loop from SIGINT handler")
    sys.stdout.flush()
    if status == pcap.PCAP_ERROR:
        # Error.  Report it.
        print("{}: pcap.dispatch: {}".format(program_name, geterr2str(pd)),
              file=sys.stderr)

    pcap.freecode(ct.byref(fcode))
    pcap.close(pd)

    return 1 if status == -1 else 0


@pcap.pcap_handler
def countme(arg, hdr, pkt):
    counterp = ct.cast(arg, ct.POINTER(ct.c_int))
    counterp[0] += 1


def usage():
    print("Usage: {} [ {} ] [ -i interface ] [ -t timeout] "
          "[ expression ]".format(program_name,
          "-mn" if is_windows else "-bmnrs"), file=sys.stderr)
    sys.exit(1)


if __name__.rpartition(".")[-1] == "__main__":
    sys.exit(main())
