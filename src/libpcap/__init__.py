# Copyright (c) 2016 Adam Karpierz
# Licensed under the BSD license
# https://opensource.org/license/bsd-3-clause

from .__about__ import * ; del __about__  # noqa
from . import __config__ ; del __config__
from .__config__ import set_config as config

from ._pcap import *  # noqa
