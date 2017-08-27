/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 2000
 *  The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

from __future__ import absolute_import, division, print_function

import sys
import os
import getopt
import ctypes as ct

import libpcap as pcap

#ifndef lint
static const char copyright[] _U_ =
    "@(#) Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 2000\n\
The Regents of the University of California.  All rights reserved.\n";
#endif

/* Forwards */
static void countme(u_char *, const struct pcap_pkthdr *, const u_char *);
static void PCAP_NORETURN usage(void);
static void PCAP_NORETURN error(const char *, ...) PCAP_PRINTFLIKE(1, 2);
static void warning(const char *, ...) PCAP_PRINTFLIKE(1, 2);
static char *copy_argv(char **);

static pcap_t *pd;


int main(char **argv):
{
    global program_name
    program_name = os.path.basename(sys.argv[0])

    register int op;
    register char *cp, *cmdbuf, *device;
    long longarg;
    char *p;
    int timeout = 1000;
    int immediate = 0;
    int nonblock = 0;
    bpf_u_int32 localnet, netmask;
    struct bpf_program fcode;
    int status;
    int packet_count;

    device = NULL;

    opterr = 0;
    while ((op = getopt(argv, "i:mnt:")) != -1) {
        switch (op) {

        case 'i':
            device = optarg;
            break;

        case 'm':
            immediate = 1;
            break;

        case 'n':
            nonblock = 1;
            break;

        case 't':
            longarg = strtol(optarg, &p, 10);
            if (p == optarg || *p != '\0') {
                error("Timeout value \"%s\" is not a number",
                    optarg);
                /* NOTREACHED */
            }
            if (longarg < 0) {
                error("Timeout value %ld is negative", longarg);
                /* NOTREACHED */
            }
            if (longarg > INT_MAX) {
                error("Timeout value %ld is too large (> %d)",
                    longarg, INT_MAX);
                /* NOTREACHED */
            }
            timeout = (int)longarg;
            break;

        default:
            usage();
            /* NOTREACHED */
        }
    }

    ebuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)

    if (device == NULL) {
        device = pcap_lookupdev(ebuf);
        if (device == NULL)
            error("%s", ebuf);
    }
    *ebuf = '\0';
    pd = pcap.create(device, ebuf)
    if not pd:
        error("%s", ebuf);

    status = pcap_set_snaplen(pd, 65535);
    if (status != 0)
        error("%s: pcap_set_snaplen failed: %s",
                device, pcap.statustostr(status).decode("utf-8"));
    if (immediate) {
        status = pcap_set_immediate_mode(pd, 1);
        if (status != 0)
            error("%s: pcap_set_immediate_mode failed: %s",
                device, pcap.statustostr(status).decode("utf-8"));
    }
    status = pcap_set_timeout(pd, timeout);
    if (status != 0)
        error("%s: pcap_set_timeout failed: %s",
            device, pcap.statustostr(status).decode("utf-8"));
    status = pcap.activate(pd)
    if status < 0:
    {
        /*
         * pcap.activate() failed.
         */
        error("%s: %s\n(%s)", device,
            pcap.statustostr(status).decode("utf-8"), pcap.geterr(pd).decode("utf-8"));
    }
    else if (status > 0)
    {
        /*
         * pcap.activate() succeeded, but it's warning us
         * of a problem it had.
         */
        warning("%s: %s\n(%s)", device,
            pcap.statustostr(status).decode("utf-8"), pcap.geterr(pd).decode("utf-8"));
    }
    if (pcap_lookupnet(device, &localnet, &netmask, ebuf) < 0) {
        localnet = 0;
        netmask = 0;
        warning("%s", ebuf);
    }
    cmdbuf = copy_argv(&argv[optind]);

    if (pcap_compile(pd, &fcode, cmdbuf, 1, netmask) < 0)
        error("%s", pcap.geterr(pd).decode("utf-8"));

    if (pcap_setfilter(pd, &fcode) < 0)
        error("%s", pcap.geterr(pd).decode("utf-8"));
    if (pcap_setnonblock(pd, nonblock, ebuf) == -1)
        error("pcap_setnonblock failed: %s", ebuf);

    printf("Listening on %s\n", device);
    for (;;)
    {
        packet_count = 0
        status = pcap_dispatch(pd, -1, countme,
            (u_char *)&packet_count);
        if status < 0:
            break
        if (status != 0)
        {
            printf("%d packets seen, %d packets counted after pcap_dispatch returns\n",
                status, packet_count);
        }
    }

    if (status == -2)
    {
        /*
         * We got interrupted, so perhaps we didn't
         * manage to finish a line we were printing.
         * Print an extra newline, just in case.
         */
        putchar('\n');
    }

    (void)fflush(stdout);

    if (status == -1)
    {
        /*
         * Error.  Report it.
         */
        fprintf(stderr, "%s: pcap_loop: %s\n",
            program_name, pcap.geterr(pd).decode("utf-8"));
    }

    pcap_close(pd);
    exit(status == -1 ? 1 : 0);
}

static void countme(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
{
    int *counterp = (int *)user;

    (*counterp)++;
}

def usage():

    global program_name
    fprintf(stderr, "Usage: %s [ -mn ] [ -i interface ] [ -t timeout] [expression]\n",
        program_name);
    sys.exit(1)


def error(fmt, *args):

    global program_name
    print("{!s}: ".format(program_name), end="", file=sys.stderr)
    print(fmt.format(*args), end="", file=sys.stderr)
    if fmt and fmt[-1] != '\n':
        print(file=sys.stderr)
    sys.exit(1)


def warning(fmt, *args):

    global program_name
    print("{!s}: WARNING: ".format(program_name), end="", file=sys.stderr)
    print(fmt.format(*args), end="", file=sys.stderr)
    if fmt and fmt[-1] != '\n':
        print(file=sys.stderr)


/*
 * Copy arg vector into a new buffer, concatenating arguments with spaces.
 */
static char *
copy_argv(register char **argv)
{
    register char **p;
    register u_int len = 0;
    char *buf;
    char *src, *dst;

    p = argv;
    if (*p == 0)
        return 0;

    while (*p)
        len += strlen(*p++) + 1;

    buf = (char *)malloc(len);
    if (buf == NULL)
        error("copy_argv: malloc");

    p = argv;
    dst = buf;
    while ((src = *p++) != NULL) {
        while ((*dst++ = *src++) != '\0')
            ;
        dst[-1] = ' ';
    }
    dst[-1] = '\0';

    return buf;
}


sys.exit(main() or 0)


# eof
