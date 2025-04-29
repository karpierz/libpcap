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
import select

import libpcap as pcap
from pcaptestutils import *  # noqa

#ifndef lint
copyright = "@(#) Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, "\
            "1995, 1996, 1997, 2000\n"\
            "The Regents of the University of California.  "\
            "All rights reserved.\n"
#endif


# Tests how select() and poll() behave on the selectable file descriptor
# for a pcap.pcap_t.
#
# This would be significantly different on Windows, as it'd test
# how WaitForMultipleObjects() would work on the event handle for a
# pcap.pcap_t.

def main(argv=sys.argv[1:]):

    global program_name
    program_name = os.path.basename(sys.argv[0])

    try:
        opts, args = getopt.getopt(argv, "i:sptnq")
    except getopt.GetoptError:
        usage()

    device = None
    doselect = False
    dopoll = False
    mechanism = None
    dotimeout = False
    dononblock = False
    quiet = False
    for opt, optarg in opts:
        if opt == '-i':
            device = optarg.encode("utf-8")
        elif opt == '-s':
            doselect = True
            mechanism = "select() and pcap.dispatch()"
        elif opt == '-p':
            dopoll = True
            mechanism = "poll() and pcap.dispatch()"
        elif opt == '-t':
            dotimeout = True
        elif opt == '-n':
            dononblock = True
        elif opt == '-q':
            quiet = True
        else:
            usage()

    expression = args

    if doselect and dopoll:
        print("selpolltest: choose select (-s) or poll (-p), but not both",
              file=sys.stderr)
        return 1
    if dotimeout and not doselect and not dopoll:
        print("selpolltest: timeout (-t) requires select (-s) or poll (-p)",
              file=sys.stderr)
        return 1

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

    pd = pcap.open_live(device, 65535, 0, 1000, ebuf)
    if not pd:
        error("{}", ebuf2str(ebuf))
    elif ebuf.value:
        warning("{}", ebuf2str(ebuf))

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

    selectable_fd = -1
    if doselect or dopoll:
        # We need either an FD on which to do select()/poll()
        # or, if there isn't one, a timeout to use in select()/
        # poll().
        try:
            selectable_fd = pcap.get_selectable_fd(pd)
        except AttributeError:
            error("pcap.get_selectable_fd is not available on this platform")
        if selectable_fd == -1:
            print("Listening on {}, using {}, with a timeout".format(
                  device2str(device), mechanism))
            try:
                required_timeout = pcap.get_required_select_timeout(pd)
            except AttributeError:
                error("pcap.get_required_select_timeout is not available "
                      "on this platform")
            if not required_timeout:
                error("select()/poll() isn't supported on {}, "
                      "even with a timeout", device2str(device))
            required_timeout = required_timeout[0]
            # As we won't be notified by select() or poll()
            # that a read can be done, we'll have to periodically
            # try reading from the device every time the required
            # timeout expires, and we don't want those attempts
            # to block if nothing has arrived in that interval,
            # so we want to force non-blocking mode.
            dononblock = True
        else:
            print("Listening on {}, using {}".format(
                  device2str(device), mechanism))
            required_timeout = None
    else:
        print("Listening on {}, using pcap.dispatch()".format(
              device2str(device)))

    if dononblock:
        if pcap.setnonblock(pd, 1, ebuf) == -1:
            error("pcap.setnonblock failed: {}", ebuf2str(ebuf))

    status = 0

    if doselect:
        while True:
            try:
                required_timeout = pcap.get_required_select_timeout(pd)
                if dotimeout:
                    seltimeout = (0 + (required_timeout.tv_usec
                                       if required_timeout is not None and
                                          required_timeout.tv_usec < 1000
                                       else 1000) / 1000000.0)
                elif required_timeout is not None:
                    seltimeout = (required_timeout.tv_sec +
                                  required_timeout.tv_usec / 1000000.0)
                else:
                    seltimeout = None
                rfds, wfds, efds = select.select([selectable_fd], [],
                                                 [selectable_fd], seltimeout)
            except OSError as exc:
                print("Select returns error ({})".format(exc.strerror))
            else:
                if not quiet:
                    if not rfds and not wfds and not efds:
                        print("Select timed out: ", end="")
                        print()  # <AK>: missing
                    else:
                        print("Select returned a descriptor: ", end="")
                        print("readable, "
                              if selectable_fd in rfds else
                              "not readable, ", end="")
                        print("exceptional condition"
                              if selectable_fd in efds else
                              "no exceptional condition", end="")
                        print()

                packet_count = ct.c_int(0)
                status = pcap.dispatch(pd, -1, countme,
                    ct.cast(ct.pointer(packet_count), ct.POINTER(ct.c_ubyte)))
                if status < 0:
                    break
                # Don't report this if we're using a
                # required timeout and we got no packets,
                # because that could be a very short timeout,
                # and we don't want to spam the user with
                # a ton of "no packets" reports.
                if (status != 0 or packet_count.value != 0 or
                    required_timeout is not None):
                    print("{:d} packets seen, {:d} packets counted after "
                          "select returns".format(status, packet_count.value))
    elif dopoll:
        while True:
            poller = select.poll()
            poller.register(selectable_fd, select.POLLIN)
            required_timeout = pcap.get_required_select_timeout(pd)
            if dotimeout:
                polltimeout = 1
            elif (required_timeout is not None and
                  required_timeout.tv_usec >= 1000):
                polltimeout = required_timeout.tv_usec // 1000
            else:
                polltimeout = None
            try:
                events = poller.poll(polltimeout)
            except OSError as exc:
                print("Poll returns error ({})".format(exc.strerror))
            else:
                if not quiet:
                    if not events:
                        print("Poll timed out")
                    else:
                        event = events[0][1]
                        print("Poll returned a descriptor: ", end="")
                        print("readable, "
                              if event & select.POLLIN else
                              "not readable, ", end="")
                        print("exceptional condition, "
                              if event & select.POLLERR else
                              "no exceptional condition, ", end="")
                        print("disconnect, "
                              if event & select.POLLHUP else
                              "no disconnect, ", end="")
                        print("invalid"
                              if event & select.POLLNVAL else
                              "not invalid", end="")
                        print()

                packet_count = ct.c_int(0)
                status = pcap.dispatch(pd, -1, countme,
                                       ct.cast(ct.pointer(packet_count),
                                               ct.POINTER(ct.c_ubyte)))
                if status < 0:
                    break
                # Don't report this if we're using a
                # required timeout and we got no packets,
                # because that could be a very short timeout,
                # and we don't want to spam the user with
                # a ton of "no packets" reports.
                if (status != 0 or packet_count.value != 0 or
                    required_timeout is not None):
                    print("{:d} packets seen, {:d} packets counted after "
                          "poll returns".format(status, packet_count.value))
    else:
        while True:
            packet_count = ct.c_int(0)
            status = pcap.dispatch(pd, -1, countme,
                                   ct.cast(ct.pointer(packet_count),
                                           ct.POINTER(ct.c_ubyte)))
            if status < 0:
                break
            print("{:d} packets seen, {:d} packets counted after "
                  "pcap.dispatch returns".format(status, packet_count.value))

    if status == pcap.PCAP_ERROR_BREAK:
        # We got interrupted, so perhaps we didn't manage to finish a
        # line we were printing. Print an extra newline, just in case.
        print()
    sys.stdout.flush()
    if status == -1:
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
    print("Usage: {} [ -sptnq ] [ -i interface ] "
          "[ expression ]".format(program_name), file=sys.stderr)
    sys.exit(1)


if __name__.rpartition(".")[-1] == "__main__":
    sys.exit(main())
