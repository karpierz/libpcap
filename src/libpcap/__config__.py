# Copyright (c) 2016-2021, Adam Karpierz
# Licensed under the BSD license
# https://opensource.org/licenses/BSD-3-Clause


def config(**cfg_dict):
    import sys
    import importlib
    module = sys.modules[__name__]
    mglobals = module.__dict__
    mglobals.update(cfg_dict)
    to_remove = {key for key, val in cfg_dict.items() if val is None}
    for key in to_remove: del mglobals[key]
    module.__all__ = tuple((set(module.__all__) | set(cfg_dict)) - to_remove)
    for mod_name in tuple(sys.modules):
        if mod_name.startswith(__package__ + ".") and mod_name != __name__:
            del sys.modules[mod_name]
    importlib.reload(sys.modules[__package__])


def make_config(cfg_fname, cfg_section=None):
    import sys
    from pathlib import Path
    from runpy import run_path
    fglobals = sys._getframe(1).f_globals
    fglobals.pop("make_config", None)
    fglobals.pop("__builtins__", None)
    fglobals.pop("__cached__",   None)
    if cfg_section is None: cfg_section = fglobals["__package__"]
    cfg_path = Path(fglobals["__file__"]).parent/cfg_fname
    cfg_dict = ({key: val for key, val in run_path(str(cfg_path)).items()
                 if not key.startswith("__")} if cfg_path.is_file() else {})
    fglobals.update(cfg_dict)
    fglobals["__all__"] = ("config",) + tuple(cfg_dict.keys())


make_config("libpcap.cfg")
