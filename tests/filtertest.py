#!/usr/bin/env python

# Copyright (c) 2016-2022, Adam Karpierz
# Licensed under the BSD license
# https://opensource.org/licenses/BSD-3-Clause

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
from libpcap._platform import defined
from pcaptestutils import *  # noqa

#ifndef lint
copyright = "@(#) Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, "\
            "1995, 1996, 1997, 2000\n"\
            "The Regents of the University of California.  "\
            "All rights reserved.\n"
#endif

MAXIMUM_SNAPLEN = 262144


def main(argv=sys.argv[1:]):

    global program_name
    program_name = os.path.basename(sys.argv[0])

    try:
        opts, args = getopt.getopt(argv, "dF:gm:Os:")
    except getopt.GetoptError:
        usage()

    if is_windows and hasattr(pcap, "wsockinit") and pcap.wsockinit() != 0:
        return 1

    dflag = 1
    if defined("BDEBUG"):
        gflag = 0
    infile = None
    netmask = pcap.PCAP_NETMASK_UNKNOWN
    Oflag = 1
    snaplen = MAXIMUM_SNAPLEN
    for opt, optarg in opts:
        if opt == '-d':
            dflag += 1
        elif opt == '-g':
            if defined("BDEBUG"):
                gflag += 1
            else:
                error("libpcap and filtertest not built with optimizer debugging enabled")
        elif opt == '-F':
            infile = optarg
        elif opt == '-O':
            Oflag = 0
        elif opt == '-m':  # !!!
            # try:
            #     addr = socket.inet_pton(socket.AF_INET, optarg)
            # except socket.error:
            #     if r == 0:                        
            #         error("invalid netmask {}", optarg)
            #     elif r == -1:
            #         error("invalid netmask {}: {}", optarg, pcap_strerror(errno))
            # else: # elif r == 1:
            #     addr = pcap.bpf_u_int32(addr)
            #     netmask = addr
            pass
        elif opt == '-s':
            try:
                long_snaplen = int(optarg)
            except:
                error("invalid snaplen {}", optarg)
            if not (0 <= long_snaplen <= MAXIMUM_SNAPLEN):
                error("invalid snaplen {}", optarg)
            elif long_snaplen == 0:  # <AK> fix, was: snaplen == 0:
                snaplen = MAXIMUM_SNAPLEN
            else:
                snaplen = long_snaplen
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
            error("invalid data link type {}", dlt_name)

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
        error("{}", geterr2str(pd))

    if not pcap.bpf_validate(fcode.bf_insns, fcode.bf_len):
        warning("Filter doesn't pass validation")

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

    pcap.freecode(ct.byref(fcode))
    pcap.close(pd)

    return 0


def read_infile(fname: str) -> bytes: 

    try:
        fd = open(fname, "rb")
    except IOError as exc:
        error("can't open {}: {}",
              fname, pcap.strerror(exc.errno).decode("utf-8", "ignore"))

    with fd:
        try:
            stat = os.fstat(fd.fileno())
        except IOError as exc:
            error("can't stat {}: {}",
                  fname, pcap.strerror(exc.errno).decode("utf-8", "ignore"))

        # _read(), on Windows, has an unsigned int byte count and an
        # int return value, so we can't handle a file bigger than
        # INT_MAX - 1 bytes (and have no reason to do so; a filter *that*
        # big will take forever to compile).  (The -1 is for the '\0' at
        # the end of the string.)
        #
        if stat.st_size > INT_MAX - 1:
            error("{} is larger than {} bytes; that's too large",
                  fname, INT_MAX - 1)
        try:
            cp = fd.read()
        except IOError as exc:
            error("read {}: {}",
                  fname, pcap.strerror(exc.errno).decode("utf-8", "ignore"))

    lcp = len(cp)
    if lcp != stat.st_size:
        error("short read {} ({:d} != {:d})", fname, lcp, stat.st_size)

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


def usage():
    print("{}, with {}".format(program_name,
          pcap.lib_version().decode("utf-8")), file=sys.stderr)
    print("Usage: {} [-d{}O] [ -F file ] [ -m netmask] [ -s snaplen ] dlt "
          "[ expression ]".format(program_name,
          "g" if defined("BDEBUG") else ""), file=sys.stderr)
    print("e.g. ./{} EN10MB host 192.168.1.1".format(program_name),
          file=sys.stderr)
    sys.exit(1)


if __name__.rpartition(".")[-1] == "__main__":
    sys.exit(main())
