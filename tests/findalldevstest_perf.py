#!/usr/bin/env python

# Copyright (c) 2016 Adam Karpierz
# SPDX-License-Identifier: BSD-3-Clause

import sys
import ctypes as ct

import libpcap as pcap
from libpcap._platform import is_windows
from pcaptestutils import *  # noqa


def main(argv=sys.argv[1:]):

    exit_status = 0

    if is_windows:
        start_ktime = win32.FILETIME()
        start_utime = win32.FILETIME()
        dummy1 = win32.FILETIME()
        dummy2 = win32.FILETIME()
        if not win32.GetProcessTimes(win32.GetCurrentProcess(),
                                     ct.byref(dummy1), ct.byref(dummy2),
                                     ct.byref(start_ktime), ct.byref(start_utime)):
          print("GetProcessTimes() fails at start", file=sys.stderr)
          return 1
        start_kticks = win32.ULARGE_INTEGER(start_ktime.dwLowDateTime +
                                            (start_ktime.dwHighDateTime >>
                                             (ct.sizeof(win32.DWORD) * 8)))
        start_uticks = win32.ULARGE_INTEGER(start_utime.dwLowDateTime +
                                            (start_utime.dwHighDateTime >>
                                             (ct.sizeof(win32.DWORD) * 8)))
    else:
        start_rusage = rusage()
        if getrusage(RUSAGE_SELF, ct.byref(start_rusage)) == -1:
          print("getrusage() fails at start", file=sys.stderr)
          return 1

    errbuf  = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE + 1)
    alldevs = ct.POINTER(pcap.pcap_if_t)()

    for _ in range(500):
        if pcap.findalldevs(ct.byref(alldevs), errbuf) == -1:
            print("Error in pcap.findalldevs: {}".format(ebuf2str(errbuf)),
                  file=sys.stderr)
            return 1
        pcap.freealldevs(alldevs)

    if is_windows:
        end_ktime = win32.FILETIME()
        end_utime = win32.FILETIME()
        dummy1 = win32.FILETIME()
        dummy2 = win32.FILETIME()
        if not win32.GetProcessTimes(win32.GetCurrentProcess(),
                                     ct.byref(dummy1), ct.byref(dummy2),
                                     ct.byref(end_ktime), ct.byref(end_utime)):
            print("GetProcessTimes() fails at end", file=sys.stderr)
            return 1
        end_kticks = win32.ULARGE_INTEGER(end_ktime.dwLowDateTime +
                                          (end_ktime.dwHighDateTime >>
                                           (ct.sizeof(win32.DWORD) * 8)))
        end_uticks = win32.ULARGE_INTEGER(end_utime.dwLowDateTime +
                                          (end_utime.dwHighDateTime >>
                                           (ct.sizeof(win32.DWORD) * 8)))
    else:
        end_rusage = rusage()
        if getrusage(RUSAGE_SELF, ct.byref(end_rusage)) == -1:
            print("getrusage() fails at end", file=sys.stderr)
            return 1

    if is_windows:
        ktime = end_kticks.value - start_kticks.value
        utime = end_uticks.value - start_uticks.value
        tottime = ktime + utime
        print("Total CPU secs: kernel %g, user %g, total %g" % (
              float(ktime)   / 10000000.0,
              float(utime)   / 10000000.0,
              float(tottime) / 10000000.0))
    else:
        ktime   = pcap.timeval()
        utime   = pcap.timeval()
        tottime = pcap.timeval()
        timersub(ct.byref(end_rusage.ru_stime), ct.byref(start_rusage.ru_stime), ct.byref(ktime))
        timersub(ct.byref(end_rusage.ru_utime), ct.byref(start_rusage.ru_utime), ct.byref(utime))
        timeradd(ct.byref(ktime), ct.byref(utime), ct.byref(tottime))
        print("Total CPU secs: kernel %g, user %g, total %g" % (
              float(ktime.tv_sec)   + float(ktime.tv_usec)   / 1000000.0,
              float(utime.tv_sec)   + float(utime.tv_usec)   / 1000000.0,
              float(tottime.tv_sec) + float(tottime.tv_usec) / 1000000.0))

    return exit_status


if __name__.rpartition(".")[-1] == "__main__":
    sys.exit(main())
