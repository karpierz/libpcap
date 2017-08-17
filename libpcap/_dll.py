# coding: utf-8

from ._platform import DLL_PATH, DLL, dlclose

try:
    dll = DLL(DLL_PATH)
except OSError as exc:
    raise exc
except Exception as exc:
    raise OSError("{}".format(exc))

# eof
