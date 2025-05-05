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

from typing import Optional
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

if is_windows:
    @win32.PHANDLER_ROUTINE
    def stop_capture(ctrltype: win32.DWORD) -> win32.BOOL:
        global pd
        pcap.breakloop(pd)
        return True
else:
    # void stop_capture(int signum _U_):
    def stop_capture(signum):
        global pd
        pcap.breakloop(pd)


def parse_interface_number(device: bytes) -> int:
    """ """
    # Search for a colon, terminating any scheme at the beginning
    # of the device.
    idx = device.find(b":")
    if idx != -1:
        # We found it.  Is it followed by "//"?
        idx += 1  # skip the :
        if device[idx:idx+2] == b"//":
            # Yes. Search for the next /, at the end of the
            # authority part of the URL.
            idx += 2  # skip the //
            idx = device[idx:].find(b"/")
            if idx != -1:
                # OK, past the / is the path.
                idx += 1  # skip the :
                device = device[idx:]
    try:
        devnum = int(device)
    except Exception:  # ValueError:
        # It's not all-numeric; return -1, so our caller
        # knows that.
        return -1
    # It's all-numeric, but is it a valid number?
    if devnum <= 0:
        # No, it's not an ordinal.
        error("Invalid adapter index")

    return devnum


def find_interface_by_number(devnum: int) -> bytes:
    """ """
    ebuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)

    devlist = ct.POINTER(pcap.pcap_if_t)()
    status = pcap.findalldevs(ct.byref(devlist), ebuf)
    if status < 0:
        error("{}", ebuf2str(ebuf))
    # Look for the devnum-th entry in the list of devices (1-based).
    dev = devlist
    for _ in range(devnum - 1):
        if not dev: break
        dev = dev.contents.next
    if not dev:
        error("Invalid adapter index")
    device = dev.contents.name
    pcap.freealldevs(devlist)

    return device


def open_interface(device: bytes, snaplen: Optional[int],
                   ebuf: ct.POINTER(ct.c_char)) -> Optional[ct.POINTER(pcap.pcap_t)]:
    """ """
    pc = pcap.create(device, ebuf)
    if not pc:
        # If this failed with "No such device", that means
        # the interface doesn't exist; return NULL, so that
        # the caller can see whether the device name is
        # actually an interface index.
        if b"No such device" in ebuf.value:
            return None
        error("{}", ebuf2str(ebuf))
    if snaplen is not None:
        status = pcap.set_snaplen(pc, snaplen)
        if status != 0:
            error("{}: pcap.set_snaplen failed: {}",
                  device2str(device), status2str(status))
    status = pcap.set_timeout(pc, 100)
    if status != 0:
        error("{}: pcap.set_timeout failed: {}",
              device2str(device), status2str(status))
    status = pcap.activate(pc)
    if status < 0:
        # pcap.activate() failed.
        cp = pcap.geterr(pc)
        if status == pcap.PCAP_ERROR:
            error("{}", cp.decode("utf-8", "ignore"))
        elif status == pcap.PCAP_ERROR_NO_SUCH_DEVICE:
            # Return an error for our caller to handle.
            src = b"%s: %s\n(%s)" % (
                  device, status2str(status).encode("utf-8"), cp)
            ct.memmove(ebuf, ct.c_char_p(src), pcap.PCAP_ERRBUF_SIZE)
        elif status == pcap.PCAP_ERROR_PERM_DENIED and cp:
            error("{}: {}\n({})",
                  device2str(device), status2str(status),
                  cp.decode("utf-8", "ignore"))
        else:
            error("{}: {}",
                  device2str(device), status2str(status))
        pcap.close(pc)
        return None

    elif status > 0:
        # pcap.activate() succeeded, but it's warning us
        # of a problem it had.
        cp = pcap.geterr(pc)
        if status == pcap.PCAP_WARNING:
            warning("{}", cp.decode("utf-8", "ignore"))
        elif status == pcap.PCAP_WARNING_PROMISC_NOTSUP and cp:
            warning("{}: {}\n({})",
                    device2str(device), status2str(status),
                    cp.decode("utf-8", "ignore"))
        else:
            warning("{}: {}",
                    device2str(device), status2str(status))

    return pc


def main(argv=sys.argv[1:]):

    global program_name
    program_name = os.path.basename(sys.argv[0])

    global pd

    try:
        opts, args = getopt.getopt(argv, "DLi:s:w:y:")
    except getopt.GetoptError:
        usage()

    show_interfaces = False
    show_dlt_types  = False
    device:   Optional[bytes] = None
    snaplen:  Optional[int]   = None
    savefile: Optional[bytes]   = None
    dlt_name: Optional[bytes] = None
    for opt, optarg in opts:
        if opt == '-D':
            show_interfaces = True
        elif opt == '-L':
            show_dlt_types = True
        elif opt == '-i':
            device = optarg.encode("utf-8")
        elif opt == '-s':
            try:
                snaplen = int(optarg)
            except Exception:  # ValueError:
                error("invalid snaplen {} (must be >= 0)", optarg)
        elif opt == '-w':
            savefile = optarg.encode("utf-8")
        elif opt == '-y':
            dlt_name = optarg.encode("utf-8")
        else:
            usage();

    expression = args

    ebuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)

    if show_interfaces:

        devlist = ct.POINTER(pcap.pcap_if_t)()
        if pcap.findalldevs(ct.byref(devlist), ebuf) < 0:
            error("{}", ebuf2str(ebuf))
        pdev = devlist ; i = 0
        while pdev:
            dev = pdev.contents
            print("{}.{}".format(i + 1, dev.name.decode("utf-8")), end="")
            if dev.description:
                print(" ({})".format(dev.description.decode("utf-8")), end="")
            print()
            pdev = dev.next ; i += 1

        pcap.freealldevs(devlist)
        return 0

    if device is None:
        devlist = ct.POINTER(pcap.pcap_if_t)()
        if pcap.findalldevs(ct.byref(devlist), ebuf) == -1:
            error("{}", ebuf2str(ebuf))
        if not devlist:
            error("no interfaces available for capture")
        device = devlist[0].name
        pcap.freealldevs(devlist)

    if show_dlt_types:

        pd = pcap.create(device, ebuf)
        if not pd:
            error("{}", ebuf2str(ebuf))
        status = pcap.activate(pd)
        if status < 0:
            # pcap.activate() failed.
            error("{}: {}\n({})",
                  device2str(device), status2str(status), geterr2str(pd))
        dlts = ct.POINTER(ct.c_int)()
        ndlts = pcap.list_datalinks(pd, ct.byref(dlts))
        if ndlts < 0:
            # pcap.list_datalinks() failed.
            error("{}: {}\n({})",
                  device2str(device), status2str(status), geterr2str(pd))

        for i in range(ndlts):
            dlt_name = pcap.datalink_val_to_name(dlts[i])
            if dlt_name is None:
                print("DLT {}".format(dlts[i]), end="")
            else:
                print("{}".format(dlt_name.decode("utf-8")), end="")
            print()

        pcap_free_datalinks(dlts)
        pcap.close(pd)
        return 0

    if savefile is None:
        error("no savefile specified")

    ebuf[0] = b"\0"

    pd = open_interface(device, snaplen, ebuf)
    if not pd:
        # That failed because the interface couldn't be found.
        #
        # If we can get a list of interfaces, and the interface name
        # is purely numeric, try to use it as a 1-based index
        # in the list of interfaces.
        devnum = parse_interface_number(device)
        if devnum == -1:
            # It's not a number; just report
            # the open error and fail.
            error("{}", ebuf2str(ebuf))

        # OK, it's a number; try to find the
        # interface with that index, and try
        # to open it.
        #
        # find_interface_by_number() exits if it
        # couldn't be found.
        device = find_interface_by_number(devnum)
        pd = open_interface(device, snaplen, ebuf)
        if not pd:
            error("{}", ebuf2str(ebuf))

    localnet = pcap.bpf_u_int32()
    netmask  = pcap.bpf_u_int32()
    if pcap.lookupnet(device, ct.byref(localnet), ct.byref(netmask), ebuf) < 0:
        localnet = pcap.bpf_u_int32(0)
        netmask  = pcap.bpf_u_int32(0)
        warning("{}",  ebuf2str(ebuf))

    if dlt_name is not None:
        dlt = pcap.datalink_name_to_val(dlt_name)
        if dlt == pcap.PCAP_ERROR:
            error("{} isn't a valid DLT name", dlt_name.decode("utf-8"))
        if pcap_set_datalink(pd, dlt) == pcap.PCAP_ERROR:
            error("{}: {}", device2str(device), geterr2str(pd))

    fcode = pcap.bpf_program()
    cmdbuf = None

    # Don't set a filter unless we were given one on the
    # command line; if capturing doesn't work, or doesn't
    # use the snapshot length, without a filter, that's
    # a bug.
    if args:
        cmdbuf = " ".join(expression).encode("utf-8")
        if pcap.compile(pd, ct.byref(fcode), cmdbuf, 1, netmask) < 0:
            error("{}", geterr2str(pd))

        if pcap.setfilter(pd, ct.byref(fcode)) < 0:
            error("{}", geterr2str(pd))

    pdd = pcap.dump_open(pd, savefile)
    if not pdd:
        error("{}", geterr2str(pd))

    if is_windows:
        win32.SetConsoleCtrlHandler(stop_capture, True)
    else:
        action = sigaction()
        action.sa_handler = stop_capture
        sigemptyset(ct.byref(action.sa_mask))
        action.sa_flags = 0
        if sigaction(SIGINT, ct.byref(action), NULL) == -1:
            error("Can't catch SIGINT: {}", strerror(errno))

    print("Listening on {}, link-type ".format(device2str(device)), end="")
    dlt = pcap.datalink(pd)
    dlt_name = pcap.datalink_val_to_name(dlt)
    if dlt_name is None:
        print("DLT {}".formt(dlt), end="")
    else:
        print("{}".format(dlt_name.decode("utf-8")), end="")
    print()
    while True:
        status = pcap.dispatch(pd, -1, pcap.dump,
                               ct.cast(pdd, ct.POINTER(ct.c_ubyte)))
        if status < 0:
            break
        if status != 0:
            print("{} packets seen".format(status))
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
    if status == -1:
        # Error.  Report it.
        print("{}: pcap.dispatch: {}".format(program_name, geterr2str(pd)),
              file=sys.stderr)
    if cmdbuf is not None:
        pcap.freecode(ct.byref(fcode))
    del cmdbuf
    pcap.close(pd)

    return 1 if status == -1 else 0


def usage():
    print("Usage: {} -D -L [ -i interface ] [ -s snaplen ] [ -w file ] "
          "[ -y dlt ] [ expression ]".format(program_name), file=sys.stderr)
    sys.exit(1)


if __name__.rpartition(".")[-1] == "__main__":
    sys.exit(main())
