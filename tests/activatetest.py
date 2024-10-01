# Copyright (c) 2016 Adam Karpierz
# SPDX-License-Identifier: BSD-3-Clause

import sys
import os
import ctypes as ct

import libpcap as pcap
from pcaptestutils import *  # noqa

CAPTURE_DEVICE = "nosuchdevice"


def main(argv=sys.argv[1:]):
    # When trying to use libpcap on a device that does not exist, the
    # expected behaviour is that pcap.create() does not return an error,
    # and pcap.activate() does return an error, and the error code
    # specifically tells that the interface does not exist.  tcpdump
    # depends on this semantics to accept integer indices instead of
    # device names.  This test provides means to verify the actual
    # behaviour, which is specific to each libpcap module.

    global CAPTURE_DEVICE
    if len(argv) >= 1: CAPTURE_DEVICE = argv[0]

    errbuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)

    print('Trying to use capture device "{}"...'.format(CAPTURE_DEVICE))
    pd = pcap.create(CAPTURE_DEVICE.encode("utf-8"), errbuf)
    if not pd:
        print("FAIL: Unexpected error from pcap.create() ({}).".format(
              ebuf2str(errbuf)), file=sys.stderr)
        return 1

    err: int = pcap.activate(pd)

    ret = 1
    if err == 0:
        print("FAIL: No error from pcap.activate().", file=sys.stderr)
    elif err == pcap.PCAP_ERROR:
        print("FAIL: Generic error from pcap.activate().", file=sys.stderr)
    elif err == pcap.PCAP_ERROR_PERM_DENIED:
        print("FAIL: Permission denied from pcap.activate(), "
              "retry with higher privileges.", file=sys.stderr)
    elif err == pcap.PCAP_ERROR_NO_SUCH_DEVICE:
        print("PASS: Correct specific error from pcap.activate().")
        ret = 0
    else:
        print("FAIL: Unexpected error {:d} from pcap.activate().".format(err),
              file=sys.stderr)

    pcap.close(pd)

    return ret


if __name__.rpartition(".")[-1] == "__main__":
    sys.exit(main())
