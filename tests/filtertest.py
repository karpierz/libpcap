#!/usr/bin/env python

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

from __future__ import absolute_import, division, print_function

import sys
import os
import getopt
import ctypes as ct

import libpcap as pcap

#ifndef lint
copyright = "@(#) Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, "\
            "1995, 1996, 1997, 2000\n"\
            "The Regents of the University of California.  "\
            "All rights reserved.\n"
rcsid = "/tcpdump/master/libpcap/filtertest.c,v 1.2 2005/08/08 17:50:13 guy"
#endif

MAXIMUM_SNAPLEN = 65535


def main(argv):

    global program_name
    program_name = os.path.basename(argv[0])

    try:
        opts, args = getopt.getopt(argv[1:], "dF:Os:")
    except getopt.GetoptError:
        usage()

    dflag = 1
    infile = None
    Oflag = 1
    snaplen = 68
    for op, optarg in opts:
        if op == '-d':
            dflag += 1
        elif op == '-F':
            infile = optarg
        elif op == '-O':
            Oflag = 0
        elif op == '-s':
            try:
                snaplen = int(optarg)
            except:
                error("invalid snaplen {}", optarg)
            if not (0 <= snaplen <= MAXIMUM_SNAPLEN):
                error("invalid snaplen {}", optarg)
            elif snaplen == 0:
                snaplen = MAXIMUM_SNAPLEN
        else:
            usage()

    if not args:
        usage()

    dlt_name = args[0]
    expression = args[1:]

    dlt = pcap.datalink_name_to_val(dlt_name.encode("utf-8"))
    if dlt < 0:
        error("invalid data link type {!s}", dlt_name)

    if infile:
        cmdbuf = read_infile(infile)
    else:
        # concatenating arguments with spaces.
        cmdbuf = " ".join(expression).encode("utf-8")

    pd = pcap.open_dead(dlt, snaplen)
    if not pd:
        error("Can't open fake pcap_t")

    fcode = pcap.bpf_program()
    if pcap.compile(pd, ct.byref(fcode), cmdbuf, Oflag, 0) < 0:
        error("{!s}", pcap.geterr(pd).decode("utf-8", "ignore"))
    pcap.bpf_dump(ct.byref(fcode), dflag)
    pcap.close(pd)

    return 0


def usage():

    global program_name
    print("{}, with {!s}".format(program_name,
          pcap.lib_version().decode("utf-8")), file=sys.stderr)
    print("Usage: {} [-dO] [ -F file ] [ -s snaplen ] dlt "
          "[ expression ]".format(program_name), file=sys.stderr)
    print("e.g. ./{} EN10MB host 192.168.1.1".format(program_name),
          file=sys.stderr)
    sys.exit(1)


def read_infile(fname): # bytes

    try:
        fd = open(fname, "rb")
    except IOError as exc:
        error("can't open {!s}: {!s}",
              fname, pcap.strerror(exc.errno).decode("utf-8", "ignore"))

    with fd:
        try:
            stat = os.fstat(fd.fileno())
        except IOError as exc:
            error("can't stat {!s}: {!s}",
                  fname, pcap.strerror(exc.errno).decode("utf-8", "ignore"))

        try:
            cp = fd.read()
        except IOError as exc:
            error("read {!s}: {!s}",
                  fname, pcap.strerror(exc.errno).decode("utf-8", "ignore"))

    lcp = len(cp)
    if lcp != stat.st_size:
        error("short read {!s} ({:d} != {:d})", fname, lcp, stat.st_size)

    cp = bytearray(cp)
    # replace "# comment" with spaces
    i = 0
    while i < lcp:
        if cp[i] == ord('#'):
            while i < lcp and cp[i] != ord('\n'):
                cp[i] = ord(' ')
                i += 1
        i += 1

    return bytes(cp)


def error(fmt, *args):

    global program_name
    print("{}: ".format(program_name), end="", file=sys.stderr)
    print(fmt.format(*args), end="", file=sys.stderr)
    if fmt and fmt[-1] != '\n':
        print(file=sys.stderr)
    sys.exit(1)


sys.exit(main(sys.argv) or 0)
