# Copyright (c) 2016-2017, Adam Karpierz
# Licensed under the BSD license
# https://opensource.org/licenses/BSD-3-Clause

from __future__ import absolute_import


def get_config(cfg_path):

    import os.path as osp
    from runpy import run_path

    return ({k: v for k, v in run_path(cfg_path).items() if not k.startswith("__")}
            if osp.isfile(cfg_path) else {})


def make_config(cfg_name):

    import sys
    import os.path as osp

    fglobals = sys._getframe(1).f_globals
    cfg_path = osp.join(osp.dirname(fglobals["__file__"]), cfg_name)
    cfg_dict = get_config(cfg_path)
    fglobals.update(cfg_dict)
    fglobals.pop("__builtins__", None)
    fglobals.pop("__cached__",   None)
    fglobals["__all__"] = tuple(cfg_dict.keys())


make_config("libpcap.cfg")
