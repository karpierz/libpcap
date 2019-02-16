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
import getopt
import ctypes as ct

import libpcap as pcap

INT_MAX = sys.maxint if sys.version_info[0] < 3 else int(2147483647)

try:
    statustostr = pcap.statustostr
except AttributeError:
    statustostr = lambda status: str(status).encode("utf-8")

#ifndef lint
copyright = "@(#) Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, "\
            "1995, 1996, 1997, 2000\n"\
            "The Regents of the University of California.  "\
            "All rights reserved.\n"
#endif


def main(argv):

    global program_name
    program_name = os.path.basename(sys.argv[0])

    try:
        opts, args = getopt.getopt(argv[1:], "i:mnt:")
    except getopt.GetoptError:
        usage()

    device = None
    immediate = False
    nonblock = 0
    timeout = 1000
    for opt, optarg in opts:
        if opt == '-i':
            device = optarg.encode("utf-8")
        elif opt == '-m':
            immediate = True
        elif opt == '-n':
            nonblock = 1
        elif opt == '-t':
            try:
                timeout = int(optarg)
            except:
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
            error("{!s}", ebuf.value.decode("utf-8", "ignore"))
        if not devlist:
            error("no interfaces available for capture")
        device = devlist[0].name
        pcap.freealldevs(devlist)

    ebuf.value = b""
    pd = pcap.create(device, ebuf)
    if not pd:
        error("{!s}", ebuf.value.decode("utf-8", "ignore"))

    status = pcap.set_snaplen(pd, 65535)
    if status != 0:
        error("{!s}: pcap.set_snaplen failed: {!s}",
              device.decode("utf-8"),
              statustostr(status).decode("utf-8", "ignore"));
    if immediate:
        try:
            status = pcap.set_immediate_mode(pd, 1)
        except AttributeError:
            error("pcap.set_immediate_mode is not available on this platform")
        if status != 0:
            error("{!s}: pcap.set_immediate_mode failed: {!s}",
                  device.decode("utf-8"),
                  statustostr(status).decode("utf-8", "ignore"));
    status = pcap.set_timeout(pd, timeout)
    if status != 0:
        error("{!s}: pcap.set_timeout failed: {!s}",
              device.decode("utf-8"),
              statustostr(status).decode("utf-8", "ignore"));

    status = pcap.activate(pd)
    if status < 0:
        # pcap.activate() failed.
        error("{!s}: {!s}\n({!s})",
              device.decode("utf-8"),
              statustostr(status).decode("utf-8", "ignore"),
              pcap.geterr(pd).decode("utf-8", "ignore"))
    elif status > 0:
        # pcap.activate() succeeded, but it's warning us
        # of a problem it had.
        warning("{!s}: {!s}\n({!s})",
                device.decode("utf-8"),
                statustostr(status).decode("utf-8", "ignore"),
                pcap.geterr(pd).decode("utf-8", "ignore"))

    localnet = pcap.bpf_u_int32()
    netmask  = pcap.bpf_u_int32()
    if pcap.lookupnet(device, ct.byref(localnet), ct.byref(netmask), ebuf) < 0:
        localnet = pcap.bpf_u_int32(0)
        netmask  = pcap.bpf_u_int32(0)
        warning("{!s}", ebuf.value.decode("utf-8", "ignore"))

    fcode = pcap.bpf_program()
    cmdbuf = " ".join(expression).encode("utf-8")
    if pcap.compile(pd, ct.byref(fcode), cmdbuf, 1, netmask) < 0:
        error("{!s}", pcap.geterr(pd).decode("utf-8", "ignore"))

    if pcap.setfilter(pd, ct.byref(fcode)) < 0:
        error("{!s}", pcap.geterr(pd).decode("utf-8", "ignore"))
    if pcap.setnonblock(pd, nonblock, ebuf) == -1:
        error("pcap.setnonblock failed: {!s}",
              ebuf.value.decode("utf-8", "ignore"))

    print("Listening on {!s}".format(device.decode("utf-8")))

    while True:
        packet_count = ct.c_int(0)
        status = pcap.dispatch(pd, -1, countme,
                 ct.cast(ct.pointer(packet_count), ct.POINTER(ct.c_ubyte)))
        if status < 0:
            break
        if status != 0:
            print("{:d} packets seen, {:d} packets counted after "
                  "pcap.dispatch returns".format(status, packet_count.value))

    if status == -2:
        # We got interrupted, so perhaps we didn't manage to finish a
        # line we were printing. Print an extra newline, just in case.
        print()
    sys.stdout.flush()
    if status == -1:
        # Error. Report it.
        print("{}: pcap.loop: {!s}".format(program_name,
              pcap.geterr(pd).decode("utf-8", "ignore")), file=sys.stderr)

    pcap.freecode(ct.byref(fcode))
    pcap.close(pd)

    return 1 if status == -1 else 0


@pcap.pcap_handler
def countme(arg, hdr, pkt):

    counterp = ct.cast(arg, ct.POINTER(ct.c_int))
    counterp[0] += 1


def usage():

    global program_name
    print("Usage: {} [ -mn ] [ -i interface ] [ -t timeout] "
          "[expression]".format(program_name), file=sys.stderr)
    sys.exit(1)


def error(fmt, *args):

    global program_name
    print("{}: ".format(program_name), end="", file=sys.stderr)
    print(fmt.format(*args), end="", file=sys.stderr)
    if fmt and fmt[-1] != '\n':
        print(file=sys.stderr)
    sys.exit(1)


def warning(fmt, *args):

    global program_name
    print("{}: WARNING: ".format(program_name), end="", file=sys.stderr)
    print(fmt.format(*args), end="", file=sys.stderr)
    if fmt and fmt[-1] != '\n':
        print(file=sys.stderr)


sys.exit(main(sys.argv) or 0)
