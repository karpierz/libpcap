# Copyright (c) 1994 Adam Karpierz
# SPDX-License-Identifier: Zlib

from ._platform import DLL_PATH, DLL
from ._platform import dlclose  # noqa: F401

try:
    dll = DLL(DLL_PATH)
except OSError as exc:  # pragma: no cover
    raise exc
except Exception as exc:  # pragma: no cover
    raise OSError("{}".format(exc)) from None
