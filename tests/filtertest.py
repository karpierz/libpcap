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
import socket
import getopt
import ctypes as ct

import libpcap as pcap
from libpcap._platform import is_windows, is_linux, defined
from pcaptestutils import *  # noqa
from pcaptestutils import error as _error
from unix import *  # noqa

#ifndef lint
copyright = "@(#) Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, "\
            "1995, 1996, 1997, 2000\n"\
            "The Regents of the University of California.  "\
            "All rights reserved.\n"
#endif

MAXIMUM_SNAPLEN = 262144
MAX_STDIN = 64 * 1024

if is_linux:
    # include <linux/filter.h>  # SKF_AD_VLAN_TAG_PRESENT
    # pcap-int.h is a private header and should not be included by programs
    # that use libpcap.  This test program uses a special hack because it is
    # the simplest way to test internal code paths that otherwise would require
    # elevated privileges.  Do not do this in normal code.
    # include <pcap-int.h>
    #
    # From <pcap-int.h>
    # BPF code generation flags.
    #
    BPF_SPECIAL_VLAN_HANDLING = 0x00000001  # special VLAN handling for Linux
    # Special handling of packet type and ifindex, which are some of the
    # auxiliary data items available in Linux >= 2.6.27.  Disregard protocol
    # and netlink attributes for now.
    #
    BPF_SPECIAL_BASIC_HANDLING = 0x00000002
# endif

cmdbuf: bytes = None
fcode:  pcap.bpf_program = None
pd:     ct.POINTER(pcap.pcap_t) = ct.POINTER(pcap.pcap_t)()

def main(argv=sys.argv[1:]):

    global program_name
    program_name = os.path.basename(sys.argv[0])

    global cmdbuf, fcode, pd

    try:
        opts, args = getopt.getopt(argv, "hdF:gm:Os:lr:")
    except getopt.GetoptError:
        usage(sys.stderr)

    if is_windows:
        wsa_data = win32.WSADATA()
        if win32.WSAStartup(win32.MAKEWORD(2, 2), ct.byref(wsa_data)) != 0:
        #if hasattr(pcap, "wsockinit") and pcap.wsockinit() != 0:
            return 1

    dflag = 1
    gflag = 0
    infile = None
    insavefile = None
    netmask = pcap.PCAP_NETMASK_UNKNOWN
    Oflag = 1
    lflag = 0
    snaplen = MAXIMUM_SNAPLEN
    for opt, optarg in opts:
        if opt == '-h':
            usage(sys.stdout)
        elif opt == '-d':
            dflag += 1
        elif opt == '-g':
            if defined("BDEBUG"):
                gflag += 1
            else:
                error("libpcap and filtertest not built with optimizer "
                      "debugging enabled", status=EX_USAGE)
        elif opt == '-F':
            infile = optarg
        elif opt == '-r':
            insavefile = optarg
        elif opt == '-O':
            Oflag = 0
        elif opt == '-m':  # !!!
            # try:
            #     addr = socket.inet_pton(socket.AF_INET, optarg)
            # except socket.error:
            #     if r == 0:
            #         error("invalid netmask {}", optarg, status=EX_DATAERR)
            #     elif r == -1:
            #         error("invalid netmask {}: {}", optarg, pcap_strerror(errno),
            #               status=EX_DATAERR)
            # else: # elif r == 1:
            #     addr = pcap.bpf_u_int32(addr)
            #     # inet_pton(): network byte order, pcap_compile(): host byte order.
            #     netmask = socket.ntohl(addr)
            pass
        elif opt == '-s':
            try:
                long_snaplen = int(optarg)
            except Exception:
                error("invalid snaplen {}", optarg, status=EX_DATAERR)
            if not (0 <= long_snaplen <= MAXIMUM_SNAPLEN):
                error("invalid snaplen {}", optarg, status=EX_DATAERR)
            elif long_snaplen == 0:  # <AK> fix, was: snaplen == 0:
                snaplen = MAXIMUM_SNAPLEN
            else:
                snaplen = long_snaplen
        elif opt == '-l':
            if is_linux:
                lflag = 1  # Enable Linux BPF extensions.
            else:
                error("libpcap and filtertest built without Linux BPF "
                      "extensions", status=EX_USAGE)
        else:
            usage(sys.stderr)

    if insavefile:
        expression = args[0:]

        if dflag > 1:
            warning("-d is a no-op with -r")
        if defined("BDEBUG") and gflag:
            warning("-g is a no-op with -r")
        if is_linux and lflag:
            warning("-l is a no-op with -r")

        errbuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)
        pd = pcap.open_offline(insavefile.encode("utf-8"), errbuf)
        if not pd:
            error("Failed opening: {}", ebuf2str(errbuf), status=EX_NOINPUT)
        del errbuf
    else:
        # Must have at least one command-line argument for the DLT.
        if not args:
            usage(sys.stderr)

        dlt_name = args[0]
        expression = args[1:]

        dlt = pcap.datalink_name_to_val(dlt_name.encode("utf-8"))
        if dlt < 0:
            try:
                dlt = int(dlt_name)
            except Exception:
                error("invalid data link type {}", dlt_name, status=EX_DATAERR)

        pd = pcap.open_dead(dlt, snaplen)
        if not pd:
            error("Can't open fake pcap_t", status=EX_SOFTWARE)

        if is_linux and lflag:
            if defined("SKF_AD_VLAN_TAG_PRESENT"):
                # Generally speaking, the fact the header defines the
                # symbol does not necessarily mean the running kernel
                # supports what is known as [vlanp] and everything
                # before it, but in this use case the filter program
                # is not meant for the kernel.
                pd.contents.bpf_codegen_flags |= BPF_SPECIAL_VLAN_HANDLING
            # endif // SKF_AD_VLAN_TAG_PRESENT
            pd.contents.bpf_codegen_flags |= BPF_SPECIAL_BASIC_HANDLING

        if defined("BDEBUG"):
            pcap.set_optimizer_debug(dflag)
            pcap.set_print_dot_graph(gflag)

    if not infile:
        # concatenating arguments with spaces.
        cmdbuf = " ".join(expression).encode("utf-8")
    elif infile != "-":
        read_infile(infile)
    else:
        read_stdin()

    fcode = pcap.bpf_program()
    if pcap.compile(pd, ct.byref(fcode), cmdbuf, Oflag, netmask) < 0:
        error("{}", geterr2str(pd), status=EX_DATAERR)

    if not pcap.bpf_validate(fcode.bf_insns, fcode.bf_len):
        warning("Filter doesn't pass validation")

    if not insavefile:
        if defined("BDEBUG"):
            # replace line feed with space
            mcodes = cmdbuf.decode("utf-8", "ignore")
            mcodes = mcodes.replace('\r', ' ').replace('\n', ' ')
            # only show machine code if BDEBUG defined, since dflag > 3
            print("machine codes for filter: {}".format(mcodes))
        pcap.bpf_dump(ct.byref(fcode), dflag)
    else:
        h = ct.POINTER(pcap.pkthdr)()
        d = ct.POINTER(ct.c_ubyte)()
        while (ret := pcap.next_ex(pd,
                                   ct.byref(h),
                                   ct.byref(d))) != pcap.PCAP_ERROR_BREAK:
            if ret == pcap.PCAP_ERROR:
                error("pcap_next_ex() failed: {}", geterr2str(pd),
                      status=EX_IOERR)
            if ret == 1:
                print("{}".format(pcap.offline_filter(ct.byref(fcode), h, d)))
            else:
                error("pcap_next_ex() failed: {}", ret, status=EX_IOERR)

    cleanup()
    if is_windows:
        # win32.WSACleanup( )  # !!!
        pass

    return EX_OK


def error(*args, **kwargs):
    cleanup()
    _error(*args, **kwargs)


def cleanup():
    # atexit() is broken on Linux/ARMv7 with TinyCC, work around by calling this
    # function explicitly just before exit() if there is a possibility any of
    # these resources have been allocated.

    global cmdbuf, fcode, pd

    cmdbuf = None
    pcap.freecode(ct.byref(fcode))
    if pd: pcap.close(pd)
    pd = ct.POINTER(pcap.pcap_t)()


def blank_comments(cp: bytes) -> bytes:
    # Replace "# comment" with spaces.
    cp  = bytearray(cp)
    i = 0 ; lcp = len(cp)
    while i < lcp:
        if cp[i] == ord('#'):
            while i < lcp and cp[i] != ord('\n'):
                cp[i] = ord(' ')
                i += 1
        i += 1
    return bytes(cp)


def read_infile(fname: str):

    global cmdbuf

    try:
        fd = open(fname, "rb")
    except IOError as exc:
        error("can't open {}: {}",
              fname, pcap.strerror(exc.errno).decode("utf-8", "ignore"),
              status=EX_NOINPUT)

    with fd:
        try:
            stat = os.fstat(fd.fileno())
        except IOError as exc:
            error("can't stat {}: {}",
                  fname, pcap.strerror(exc.errno).decode("utf-8", "ignore"),
                  status=EX_NOINPUT)

        # _read(), on Windows, has an unsigned int byte count and an
        # int return value, so we can't handle a file bigger than
        # INT_MAX - 1 bytes (and have no reason to do so; a filter *that*
        # big will take forever to compile).  (The -1 is for the '\0' at
        # the end of the string.)
        #
        if stat.st_size > INT_MAX - 1:
            error("{} is larger than {} bytes; that's too large",
                  fname, INT_MAX - 1, status=EX_DATAERR)
        try:
            cp = fd.read()
        except IOError as exc:
            error("read {}: {}",
                  fname, pcap.strerror(exc.errno).decode("utf-8", "ignore"),
                  status=EX_IOERR)
    cmdbuf = cp

    lcp = len(cp)
    if lcp != stat.st_size:
        error("short read {} ({:d} != {:d})", fname, lcp, stat.st_size,
              status=EX_IOERR)

    cmdbuf = blank_comments(cp)


def read_stdin():
    # Copy stdin into a size-limited buffer.

    global cmdbuf

    try:
        cp = fd.read()
    except IOError as exc:
        error("failed reading from stdin", status=EX_IOERR)

    cmdbuf = cp

    if len(cp) > MAX_STDIN:
        error("received more than {:d} bytes on stdin", MAX_STDIN,
              status=EX_DATAERR)

    # No error, all data is within the buffer and NUL-terminated.
    cmdbuf = blank_comments(cp)


def usage(file):
    print("{}, with {}".format(program_name,
          pcap.lib_version().decode("utf-8")), file=file)
    print("Usage: {} [-d{}O{}] [ -F file ] [ -m netmask] [ -s snaplen ] dlt "
          "[ expr ]".format(program_name,
          "g" if defined("BDEBUG") else "",
          "l" if is_linux else ""), file=file)
    print("       (print the filter program bytecode)", file=file)
    print("  or:  {} [-O] [ -F file ] [ -m netmask] -r file "
          "[ expression ]".format(program_name), file=file)
    print("       (print the filter program result for each packet)",
          file=file)
    print("  or:  {} -h".format(program_name), file=file)
    print("       (print the detailed help screen)", file=file)
    if file is not sys.stdout:
        sys.exit(EX_USAGE)
    print("\nOptions specific to {}:".format(program_name), file=file)
    print("  <dlt>           a valid DLT name, e.g. 'EN10MB'", file=file)
    print("  <expr>          a valid filter expression, e.g. "
          "'tcp port 80'", file=file)
    if is_linux:
        print("  -l              allow the use of Linux BPF extensions",
              file=file)
    if defined("BDEBUG"):
        print("  -g              print Graphviz dot graphs for the "
              "optimizer steps", file=file)
    print("  -m <netmask>    use this netmask for pcap_compile(), "
          "e.g. 255.255.255.0", file=file)
    print("\nOptions common with tcpdump:", file=file)
    print("  -d              change output format (accumulates, one -d "
          "is implicit)", file=file)
    print("  -O              do not optimize the filter program",
          file=file)
    print("  -F <file>       read the filter expression from the "
          "specified file", file=file)
    print("                  (\"-\" means stdin and allows at most %u "
          "characters)".format(MAX_STDIN), file=file)
    print("  -s <snaplen>    set the snapshot length", file=file)
    print("  -r <file>       read the packets from this savefile",
          file=file)
    print("\nIf no filter expression is specified, it defaults to an "
          "empty string, which", file=file)
    print("accepts all packets.  If the -F option is in use, it replaces "
          "any filter", file=file)
    print("expression specified as a command-line argument.", file=file)
    sys.exit(EX_OK)


if __name__.rpartition(".")[-1] == "__main__":
    sys.exit(main())
