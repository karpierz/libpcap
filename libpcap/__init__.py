# coding: utf-8

from .__about__ import * ; del __about__
from ._platform import is_windows, defined

WPCAP       = True #!!!
HAVE_REMOTE = True #!!!

from ._pcap import *
if is_windows and defined("WPCAP"):
    from ._win32_ext import *
if defined("HAVE_REMOTE"):
    from ._remote_ext import *

# eof
