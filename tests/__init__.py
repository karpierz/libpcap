# Copyright (c) 2016-2021, Adam Karpierz
# Licensed under the BSD license
# https://opensource.org/licenses/BSD-3-Clause

__all__ = ('top_dir', 'test_dir')

import sys, pathlib
sys.dont_write_bytecode = True
test_dir = pathlib.Path(__file__).resolve().parent
top_dir = test_dir.parent
del sys, pathlib
