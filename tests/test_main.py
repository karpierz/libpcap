# Copyright (c) 2016 Adam Karpierz
# SPDX-License-Identifier: BSD-3-Clause

import unittest

import libpcap
from libpcap.__config__ import config
from utlx.platform import is_windows


class MainTestCase(unittest.TestCase):

    def setUp(self):
        pass

    def test_versiontest(self):
        from .versiontest import main
        result = main()
        self.assertEqual(result, 0)

    @unittest.skipUnless(is_windows, "Windows-only test for now...")
    def test_findalldevstest(self):
        from .findalldevstest import main
        result = main()
        self.assertEqual(result, 0)

    @unittest.skipUnless(is_windows, "Windows-only test for now...")
    def test_findalldevstest_perf(self):
        from .findalldevstest_perf import main
        result = main()
        self.assertEqual(result, 0)

    @unittest.skipIf(is_windows and config.get("LIBPCAP") in ["wpcap", "tcpdump"],
                     "Skip for old wpcap library or tcpdump library on Windows...")
    def test_opentest(self):
        from .opentest import main
        result = main()
        self.assertEqual(result, 0)
