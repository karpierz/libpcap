# Copyright (c) 2016 Adam Karpierz
# SPDX-License-Identifier: BSD-3-Clause

import unittest

import libpcap


class MainTestCase(unittest.TestCase):

    def setUp(self):
        pass

    def test_versiontest(self):
        from .versiontest import main
        result = main()
        self.assertEqual(result, 0)

    def test_findalldevstest(self):
        from .findalldevstest import main
        result = main()
        self.assertEqual(result, 0)

    def test_findalldevstest_perf(self):
        from .findalldevstest_perf import main
        result = main()
        self.assertEqual(result, 0)

    def test_opentest(self):
        from .opentest import main
        result = main()
        self.assertEqual(result, 0)
