#!/usr/bin/env python

# coding: utf-8

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

#ifndef lint
copyright = "@(#) Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, "\
            "1995, 1996, 1997, 2000\n"\
            "The Regents of the University of California.  "\
            "All rights reserved.\n"
#endif

/*
 * Tests how select() and poll() behave on the selectable file descriptor
 * for a pcap_t.
 *
 * This would be significantly different on Windows, as it'd test
 * how WaitForMultipleObjects() would work on the event handle for a
 * pcap_t.
 */
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#else
#include <sys/time.h>   /* older UN*Xes */
#endif
#include <poll.h>

/* Forwards */
static void countme(u_char *, const struct pcap_pkthdr *, const u_char *);
static char *copy_argv(char **);

static pcap_t *pd;


def main(argv):

    global program_name
    program_name = os.path.basename(sys.argv[0])

    try:
        opts, args = getopt.getopt(argv[1:], "i:sptn")
    except getopt.GetoptError:
        usage()

    register int op;
    bpf_u_int32 localnet, netmask;
    register char *cp, *cmdbuf, *device;
    int doselect, dopoll, dotimeout, dononblock;
    struct bpf_program fcode;
    int selectable_fd;
    int status;
    int packet_count;

    device = None
    doselect = False
    dopoll = False
    dotimeout = False
    dononblock = False
    for op, optarg in opts:
        if op == '-i':
            device = optarg.encode("utf-8")
        elif op == '-s':
            doselect = True
        elif op == '-p':
            dopoll = True
        elif op == '-t':
            dotimeout = True
        elif op == '-n':
            dononblock = True
        elset:
            usage()

    if doselect && dopoll:
        fprintf(stderr, "selpolltest: choose select (-s) or poll (-p), but not both\n");
        return 1;
    if dotimeout && !doselect && not dopoll:
        fprintf(stderr, "selpolltest: timeout (-t) requires select (-s) or poll (-p)\n");
        return 1;

    ebuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)

    if device is None:
        device = pcap.lookupdev(ebuf)
        if device is None:
            error("{!s}", ebuf.value.decode("utf-8", "ignore"))

    ebuf.value = b""
    pd = pcap.open_live(device, 65535, 0, 1000, ebuf)
    if not pd:
        error("{!s}", ebuf.value.decode("utf-8", "ignore"))
    elif ebuf.value:
        warning("{!s}", ebuf.value.decode("utf-8", "ignore"))

    if pcap.lookupnet(device, ct.byref(localnet), ct.byref(netmask), ebuf) < 0:
        localnet = 0
        netmask = 0
        warning("{!s}", ebuf.value.decode("utf-8", "ignore"))

    cmdbuf = copy_argv(&argv[optind]);

    if pcap.compile(pd, ct.byref(fcode), cmdbuf, 1, netmask) < 0:
        error("{!s}", pcap.geterr(pd).decode("utf-8", "ignore"))

    if pcap.setfilter(pd, ct.byref(fcode)) < 0:
        error("{!s}", pcap.geterr(pd).decode("utf-8", "ignore"))
    if pcap_get_selectable_fd(pd) == -1:
        error("pcap_get_selectable_fd() fails")
    if dononblock:
        if pcap.setnonblock(pd, 1, ebuf) == -1:
            error("pcap.setnonblock failed: {!s}",
                  ebuf.value.decode("utf-8", "ignore"))

    selectable_fd = pcap_get_selectable_fd(pd)

    print("Listening on {!s}".format(device.decode("utf-8", "ignore")))

    if doselect:
    {
        while True:
        {
            fd_set setread, setexcept;
            struct timeval seltimeout;

            FD_ZERO(&setread);
            FD_SET(selectable_fd, &setread);
            FD_ZERO(&setexcept);
            FD_SET(selectable_fd, &setexcept);
            if (dotimeout) {
                seltimeout.tv_sec = 0;
                seltimeout.tv_usec = 1000;
                status = select(selectable_fd + 1, &setread,
                    NULL, &setexcept, &seltimeout);
            } else {
                status = select(selectable_fd + 1, &setread,
                    NULL, &setexcept, NULL);
            }
            if (status == -1) {
                printf("Select returns error (%s)\n",
                    strerror(errno));
            } else {
                if (status == 0)
                    printf("Select timed out: ");
                else
                    printf("Select returned a descriptor: ");
                if (FD_ISSET(selectable_fd, &setread))
                    printf("readable, ");
                else
                    printf("not readable, ");
                if (FD_ISSET(selectable_fd, &setexcept))
                    printf("exceptional condition\n");
                else
                    printf("no exceptional condition\n");
                packet_count = 0
                status = pcap.dispatch(pd, -1, countme, (u_char *)&packet_count)
                if status < 0:
                    break
                printf("%d packets seen, %d packets counted after select returns\n",
                    status, packet_count);
            }
        }
    }
    elif dopoll:
    {
        while True:
        {
            struct pollfd fd;
            int polltimeout;

            fd.fd = selectable_fd;
            fd.events = POLLIN;
            if (dotimeout)
                polltimeout = 1;
            else
                polltimeout = -1;
            status = poll(&fd, 1, polltimeout);
            if (status == -1) {
                printf("Poll returns error (%s)\n",
                    strerror(errno));
            } else {
                if (status == 0)
                    printf("Poll timed out\n");
                else {
                    printf("Poll returned a descriptor: ");
                    if (fd.revents & POLLIN)
                        printf("readable, ");
                    else
                        printf("not readable, ");
                    if (fd.revents & POLLERR)
                        printf("exceptional condition, ");
                    else
                        printf("no exceptional condition, ");
                    if (fd.revents & POLLHUP)
                        printf("disconnect, ");
                    else
                        printf("no disconnect, ");
                    if (fd.revents & POLLNVAL)
                        printf("invalid\n");
                    else
                        printf("not invalid\n");
                }
                packet_count = 0
                status = pcap.dispatch(pd, -1, countme, (u_char *)&packet_count)
                if status < 0:
                    break
                printf("%d packets seen, %d packets counted after poll returns\n",
                    status, packet_count);
            }
        }
    }
    else:

        while True:
        {
            packet_count = 0
            status = pcap.dispatch(pd, -1, countme, (u_char *)&packet_count)
            if status < 0:
                break
            printf("%d packets seen, %d packets counted after pcap.dispatch returns\n",
                status, packet_count);
        }

    if status == -2:
        # We got interrupted, so perhaps we didn't manage to finish a
        # line we were printing. Print an extra newline, just in case.
        print()
    sys.stdout.flush()
    if status == -1:
        # Error. Report it.
        print("{}: pcap_loop: {!s}".format(program_name,
              pcap.geterr(pd).decode("utf-8", "ignore")), file=sys.stderr)

    pcap.close(pd)

    exit(status == -1 ? 1 : 0);


static void countme(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
{
    int *counterp = (int *)user;

    (*counterp)++;
}

def usage():

    global program_name
    print("Usage: {!s} [ -sptn ] [ -i interface ] [expression]".format(
          program_name), file=sys.stderr)
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


# eof
