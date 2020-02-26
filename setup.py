# Copyright (c) 2016-2020, Adam Karpierz
# Licensed under the BSD license
# https://opensource.org/licenses/BSD-3-Clause

from os import path
from io import open
from glob import glob
from setuptools import setup

top_dir = path.dirname(path.abspath(__file__))
with open(glob(path.join(top_dir, "src/*/__about__.py"))[0],
          encoding="utf-8") as f:
    class about: exec(f.read(), None)

setup(
    name             = about.__title__,
    version          = about.__version__,
    description      = about.__summary__,
    url              = about.__uri__,
    download_url     = about.__uri__,

    author           = about.__author__,
    author_email     = about.__email__,
    maintainer       = about.__maintainer__,
    maintainer_email = about.__email__,
    license          = about.__license__,
)
