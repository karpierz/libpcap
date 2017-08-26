# coding: utf-8

__all__ = ('__title__', '__summary__', '__uri__', '__version_info__',
           '__version__', '__author__', '__email__', '__copyright__',
           '__license__')

__title__        = "libpcap"
__summary__      = "Python wrapper for the libpcap C library (ctypes/cffi-based libpcap)"
__uri__          = "http://pypi.python.org/pypi/libpcap/"
__version_info__ = type("version_info", (), dict(serial=16,
                        major=1, minor=0, micro=0, releaselevel="alpha"))
__version__      = "{0.major}.{0.minor}.{0.micro}{1}{2}".format(__version_info__,
                   dict(final="", alpha="a", beta="b", rc="rc")[__version_info__.releaselevel],
                   "" if __version_info__.releaselevel == "final" else __version_info__.serial)
__author__       = "Adam Karpierz"
__email__        = "python@python.pl"
__copyright__    = "Copyright (c) 2016-2017, {0}".format(__author__)
__license__      = "BSD license"

# eof
