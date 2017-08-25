# coding: utf-8

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

from __future__ import absolute_import, print_function

import sys
import os
import argparse

#ifndef lint
copyright = """@(#) Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 2000
The Regents of the University of California.  All rights reserved.
"""
rcsid = "/tcpdump/master/libpcap/filtertest.c,v 1.2 2005/08/08 17:50:13 guy"
#endif


def read_infile(fname): # bytes

    try:
        fd = open(fname, "rb")
    except IOError as exc:
        error("can't open {!s}: {!s}", fname, pcap.strerror(exc.errno))

    with fd:
        try:
            stat = os.fstat(fd.fileno())
        except IOError as exc:
            error("can't stat {!s}: {!s}", fname, pcap.strerror(exc.errno))

        try:
            cp = fd.read()
        except IOError as exc:
            error("read {!s}: {!s}", fname, pcap.strerror(exc.errno))

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

    print("{!s}: ".format(program_name), end="", file=sys.stderr)
    print(fmt.format(*args), end="", file=sys.stderr)
    if fmt and fmt[-1] != '\n':
        print(file=sys.stderr)
    sys.exit(1)


def usage():

    print("{!s}, with {!s}".format(program_name, pcap.lib_version()), file=sys.stderr)
    print("Usage: {!s} [-dO] [ -F file ] [ -s snaplen ] dlt [ expression ]".format(program_name), file=sys.stderr)
    sys.exit(1)


#extern optind = 0  # int

def main():

    dflag   = 1
    infile  = None
    Oflag   = 1
    snaplen = 68

    parser = argparse.ArgumentParser()
    program_name = parser.prog
    parser.add_argument("-d", action="store_true")
    parser.add_argument("-F", type=str)
    parser.add_argument("-O", action="store_true")
    parser.add_argument("-s", type=int)
    parser.add_argument("dlt", type=str)
    args = parser.parse_args()
    print(parser)
    return

    #while False: #!!!((op = getopt(sys.argv, "dF:Os:")) != -1):

    if args.d:
        dflag += 1

    if args.F is not None:
        infile = args.F

    if args.O:
        Oflag = 0

    if args.s is not None:
        snaplen = args.s
        if not (0 <= snaplen <= 65535):
            error("invalid snaplen {!s}", optarg)
        elif snaplen == 0:
            snaplen = 65535

    #else:
    #    usage()

    if optind >= len(sys.argv):
        usage()

    dlt_name = sys.argv[optind]
    another_args = sys.argv[optind + 1:]

    dlt = pcap.datalink_name_to_val(dlt_name)
    if dlt < 0:
        error("invalid data link type {!s}", dlt_name)
    
    if infile:
        cmdbuf = read_infile(infile)
    else:
        # concatenating arguments with spaces.
        cmdbuf = " ".join(another_args)

    pd = pcap.open_dead(dlt, snaplen)
    if pd is None:
        error("Can't open fake pcap_t")

    fcode = pcap.bpf_program()
    if pcap.compile(pd, ct.byref(fcode), cmdbuf, Oflag, 0) < 0:
        error("{!s}", pcap.geterr(pd))
    pcap.bpf_dump(ct.byref(fcode), dflag)
    pcap.close(pd)

    sys.exit(0)


main()


# eof
