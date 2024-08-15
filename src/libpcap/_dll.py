# Copyright (c) 2016 Adam Karpierz
# SPDX-License-Identifier: BSD-3-Clause

from ._platform import DLL_PATH, DLL, dlclose

try:
    dll = DLL(DLL_PATH)
except OSError as exc:  # pragma: no cover
    raise exc
except Exception as exc:  # pragma: no cover
    raise OSError("{}".format(exc)) from None
