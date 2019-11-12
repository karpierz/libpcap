# Copyright (c) 2016-2019, Adam Karpierz
# Licensed under the BSD license
# https://opensource.org/licenses/BSD-3-Clause/

__all__ = ('top_dir', 'test_dir')

import sys, os
sys.dont_write_bytecode = True
test_dir = os.path.dirname(os.path.abspath(__file__))
top_dir = os.path.dirname(test_dir)
del sys, os
