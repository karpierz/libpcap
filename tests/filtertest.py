#!/usr/bin/env python

# Copyright (c) 2016-2017, Adam Karpierz
# Licensed under the BSD license
# http://opensource.org/licenses/BSD-3-Clause

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
from libpcap._platform import is_windows, defined

#ifndef lint
copyright = "@(#) Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, "\
            "1995, 1996, 1997, 2000\n"\
            "The Regents of the University of California.  "\
            "All rights reserved.\n"
#endif

MAXIMUM_SNAPLEN = 65535


def main(argv):

    global program_name
    program_name = os.path.basename(argv[0])

    try:
        opts, args = getopt.getopt(argv[1:], "dF:m:Os:")
    except getopt.GetoptError:
        usage()

    have_fcode = False
    if defined("BDEBUG"):
        # if optimizer debugging is enabled, output DOT graph
        # `dflag=4' is equivalent to -dddd to follow -d/-dd/-ddd
        # convention in tcpdump command line
        dflag = 4
    else:
        dflag = 1
    infile = None
    netmask = pcap.PCAP_NETMASK_UNKNOWN
    Oflag = 1
    snaplen = 68
    for op, optarg in opts:
        if op == '-d':
            dflag += 1
        elif op == '-F':
            infile = optarg
        elif op == '-O':
            Oflag = 0
        elif op == '-m':
            # addr = inet_addr(optarg) # in_addr_t
            # if addr == (in_addr_t)(-1):
            #     error("invalid netmask {}", optarg)
            # netmask = addr
            pass
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
        try:
            dlt = int(dlt_name)
        except:
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
    if pcap.compile(pd, ct.byref(fcode), cmdbuf, Oflag, netmask) < 0:
        error("{!s}", pcap.geterr(pd).decode("utf-8", "ignore"))
    have_fcode = True

    if not pcap.bpf_validate(fcode.bf_insns, fcode.bf_len):
        warn("Filter doesn't pass validation")

    if defined("BDEBUG"):
        if cmdbuf:
            # replace line feed with space
            mcodes = cmdbuf.decode("utf-8", "ignore")
            mcodes = mcodes.replace('\r', ' ').replace('\n', ' ')
            # only show machine code if BDEBUG defined, since dflag > 3
            print("machine codes for filter: {}".format(mcodes))
        else:
            print("machine codes for empty filter:")

    pcap.bpf_dump(ct.byref(fcode), dflag)
    del cmdbuf
    if have_fcode:
        pcap.freecode(ct.byref(fcode))
    pcap.close(pd)

    return 0


def usage():

    global program_name
    print("{}, with {!s}".format(program_name,
          pcap.lib_version().decode("utf-8")), file=sys.stderr)
    print("Usage: {} [-dO] [ -F file ] [ -m netmask] [ -s snaplen ] dlt "
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


def warn(fmt, *args):

    global program_name
    print("{}: WARNING: ".format(program_name), end="", file=sys.stderr)
    print(fmt.format(*args), end="", file=sys.stderr)
    if fmt and fmt[-1] != '\n':
        print(file=sys.stderr)


sys.exit(main(sys.argv) or 0)
