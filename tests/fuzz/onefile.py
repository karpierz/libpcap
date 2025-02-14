# Copyright (c) 2016 Adam Karpierz
# SPDX-License-Identifier: BSD-3-Clause

import sys
import os
import ctypes as ct


def main(argv=sys.argv[1:]):

    if len(argv) == 2:
        if fuzz_openFile: fuzz_openFile(argv[1])
    elif len(argv) != 1:
        return 1

    # opens the file, get its size, and reads it into a buffer

    try:
        file = open(argv[0], "rb")
    except Exception:
        return 2

    with file:

        try:
            file.seek(0, os.SEEK_END)
            size = file.tell()
            file.seek(0, os.SEEK_SET)
        except Exception:
            return 2
        if size == ct.c_size_t(-1).value:
            return 2

        try:
            data = file.read(size)
        except Exception:
            return 2
        if data is None or len(data) != size:
            return 2

        # launch fuzzer
        LLVMFuzzerTestOneInput(data)

    return 0
