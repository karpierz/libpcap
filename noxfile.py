# Copyright (c) 2025 Adam Karpierz
# SPDX-License-Identifier: Zlib

# /// script
# dependencies = ["nox>=2025.11.12", "nox_ext", "nox_lib"]
# ///

from __future__ import annotations

from typing import Any
import sys
import os
from pathlib import Path
from functools import partial
import shutil
import subprocess
import warnings

import nox
import nox_ext
from nox_ext import print, pprint

here = Path(__file__).resolve().parent
env  = os.environ

# Configuration

PKG = nox.get_package_data(here)

PYPROJECT   = nox.project.load_toml("pyproject.toml")
PY_VERSIONS = nox.project.python_versions(PYPROJECT)
PY_DEFAULT  = "3.13"

# Prevent Python from writing bytecode
env["PYTHONDONTWRITEBYTECODE"] = "1"
# env["PKG_INITIAL_BUILD"] = "1"

# Helpers & Utils

copytree = shutil.copytree
rmtree   = partial(shutil.rmtree, ignore_errors=True)

# Sessions

@nox.session(python=[PY_DEFAULT], default=False,
    requires=["cleanup"])
def prepare(session: nox.Session) -> None:
    """Preparing the repository"""
    cmd = here/".aprep.cmd"
    if cmd.is_file(): subprocess.run([cmd])

@nox.session(python=[PY_DEFAULT], default=False)
def cleanup(session: nox.Session) -> None:
    """Cleaning the repository"""
#no_package = true
    cmd = here/".clean.cmd"
    if cmd.is_file(): subprocess.run([cmd], stderr=subprocess.DEVNULL)
    rmtree(here/"build")
    rmtree(here/"dist"),
    for item in here.glob("src/*.egg-info"): rmtree(item)
    for item in here.glob("**/__pycache__"): rmtree(item)
    for item in here.glob("**/.mypy_cache"): rmtree(item)
    rmtree(here/".tox")
    rmtree(here/".nox")

@nox.session(python=[*PY_VERSIONS, "pypy3.10", "pypy3.11"])
def tests(session: nox.Session) -> None:
    """Running tests"""
    session.install(".", "--group=test")
    session.py("--version")
    session.py("-m", "tests", *session.posargs)

@nox.session(python=[PY_DEFAULT], default=False)
def coverage(session: nox.Session) -> None:
    """Running code coverage analysis"""
    session.install(".", "--group=coverage")
    session.py("-m", "coverage", "erase")
    session.py("-m", "coverage", "run", "-m", "tests", *session.posargs, success_codes=range(0, 256))
    session.py("-m", "coverage", "html", success_codes=range(0, 256))
    session.py("-m", "coverage", "report")

@nox.session(python=[PY_DEFAULT])
def docs(session: nox.Session) -> None:
    """Building documentation and running doc tests"""
    session.install(".", "--group=docs")
    html_dir = here/"build/docs/html"
    session.py("-m", "sphinxlint", "-i", "#arch", "-i", ".nox", "-i", ".tox",
                                   "-i", "build", "-i", "dist", "-i", ".mypy_cache")
    #session.run("python","-m", "sphinx.apidoc", "-f", *[session.site_packages/f"{item}/"
    #                                                    for item in PKG.TOP_LEVELS])
    session.py("-m", "sphinx.cmd.build", "-W", "-a", "-b", "html", "-E", here/"docs", html_dir)
    session.py("-m", "sphinx.cmd.build", "-W", "-a", "-b", "doctest",    here/"docs", html_dir)
    session.py("-m", "sphinx.cmd.build", "-W", "-a", "-b", "linkcheck",  here/"docs", html_dir)

@nox.session(python=[PY_DEFAULT], default=False,
    requires=["tests", "docs"])
def build(session: nox.Session) -> None:
    """Building the package"""
    session.install("--group=build")
    session.py("-m", "check_manifest", "-v", "--ignore-bad-ideas", "*.so")
    session.py("-m", "build")
    # Verify distribution files
    session.py("-m", "twine", "check", "dist/*")

@nox.session(python=[PY_DEFAULT], default=False,
    requires=["build"])
def publish(session: nox.Session) -> None:
    """Publishing the package and documentation"""
    session.install("--group=publish")
    # Publish on PyPI
    session.py("-m", "twine", "upload", "dist/*")
    # Publish documentation on GitHub Pages
    # checkout gh-pages worktree
    env_dir = Path(session.virtualenv.location)
    gh_pages_dir = env_dir/"gh-pages"
    rmtree(gh_pages_dir)
    session.run("git", "worktree", "prune")
    #session.run("git", "worktree", "add", gh_pages_dir, "gh-pages")
    session.run("git", "worktree", "add", "-B", "gh-pages", gh_pages_dir)
    # clean old docs
    (gh_pages_dir/".nojekyll").touch()
    for fpath in gh_pages_dir.iterdir():
        if fpath.name not in (".git",".nojekyll"):
            if fpath.is_dir():
                rmtree(fpath)
            else:
                fpath.unlink(missing_ok=True)
    # copy new docs
    copytree(here/"build/docs/html", gh_pages_dir, dirs_exist_ok=True)
    # commit + push
    session.run("git", "-C", gh_pages_dir, "add", ".")
    session.run("git", "-C", gh_pages_dir, "commit", "-m", "Update documentation")
    session.run("git", "-C", gh_pages_dir, "push", "--force", "origin", "gh-pages")
    # remove worktree
    session.run("git", "worktree", "remove", "--force", gh_pages_dir)
    rmtree(gh_pages_dir)
    session.run("git", "worktree", "prune")

@nox.session(python=[PY_DEFAULT])
def typing(session: nox.Session) -> None:
    """Static type checking"""
    session.install(".", "--group=typing")
    session.py("-m", "mypy")

@nox.session(python=[PY_DEFAULT])
def lint(session: nox.Session) -> None:
    """Checking code style and quality"""
    session.install(".", "--group=lint")
    session.py("-m", "flake8", here/"src/")
