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
import ctypes as ct

import libpcap as pcap
from libpcap._platform._limits import *  # noqa
from libpcap._platform import is_windows
if is_windows: from libpcap._platform._windows import _win32 as win32

#ifndef lint
copyright = "@(#) Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, "\
            "1995, 1996, 1997, 2000\n"\
            "The Regents of the University of California.  "\
            "All rights reserved.\n"
#endif

if is_windows:

    # Generate a string for a Win32-specific error (i.e. an error generated when
    # calling a Win32 API).
    # For errors occurred during standard C calls, we still use pcap.strerror()

    ERRBUF_SIZE = 1024

    def strerror(code) -> str:
        error  = win32.DWORD(error)
        errbuf = ct.create_string_buffer(ERRBUF_SIZE + 1)
        #static char errbuf[ERRBUF_SIZE+1];
        win32.FormatMessageA(win32.FORMAT_MESSAGE_FROM_SYSTEM,
                             None, error, 0, errbuf,
                             ERRBUF_SIZE, None)
        # "FormatMessage()" "helpfully" sticks CR/LF at the end of the
        # message.  Get rid of it.
        errlen = len(errbuf)
        if errlen >= 2:
            errbuf[errlen - 1] = b'\0'
            errbuf[errlen - 2] = b'\0'
            errlen -= 2

        return errbuf.value.decode()
       #return errbuf

    def sleep_secs(secs: int):
        win32.Sleep(secs * 1000)

else:

    def strerror(code) -> str:
        try:
            return os.strerror(code)
        except ValueError:
            return f"Unknown error (code: {code})"

    def sleep_secs(secs: int):
        if secs <= 0: return
        secs_remaining = secs # (unsigned int) secs
        while secs_remaining != 0:
            secs_remaining = sleep(secs_remaining)

if hasattr(pcap, "statustostr"):
    status2str = lambda status: pcap.statustostr(status).decode("utf-8", "ignore")
else:
    status2str = lambda status: str(status)
device2str = lambda device: device.decode("utf-8")
ebuf2str   = lambda ebuf: ebuf.value.decode("utf-8", "ignore")
geterr2str = lambda pd: pcap.geterr(pd).decode("utf-8", "ignore")


def error(fmt, *args, status=1):
    program_name = sys._getframe(1).f_globals["program_name"]
    print("{}: ".format(program_name), end="", file=sys.stderr)
    print(fmt.format(*args), end="", file=sys.stderr)
    if fmt and fmt[-1] != '\n':
        print(file=sys.stderr)
    sys.exit(status)


def warning(fmt, *args):
    program_name = sys._getframe(1).f_globals["program_name"]
    print("{}: WARNING: ".format(program_name), end="", file=sys.stderr)
    print(fmt.format(*args), end="", file=sys.stderr)
    if fmt and fmt[-1] != '\n':
        print(file=sys.stderr)


del is_windows
