# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

import re
from pathlib import Path
from setuptools.config import read_configuration
from packaging import version

top_dir = Path(__file__).resolve().parents[1]
metadata = read_configuration(top_dir/"setup.cfg",
                              ignore_option_errors=True)["metadata"]
copyr_patt = r"^\s*__copyright__\s*=\s*"
class about:
    __title__      = metadata["name"]
    __summary__    = metadata.get("description")
    __uri__        = metadata.get("url")
    __version__    = str(version.parse(metadata["version"]))
    __author__     = metadata.get("author")
    __maintainer__ = metadata.get("maintainer")
    __email__      = metadata.get("author_email")
    __license__    = metadata.get("license")
    __copyright__  = eval(next((re.split(copyr_patt, line)[1] for line in
                                next(top_dir.glob("src/**/__about__.py"))
                                .open("rt", encoding="utf-8")
                                if re.split(copyr_patt, line)[1:]), "None"))
del read_configuration, version, metadata, copyr_patt

def setup(app):
    pass

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
# import os
# import sys
# sys.path.insert(0, os.path.abspath('.'))


# -- Project information -----------------------------------------------------

project   = about.__title__
copyright = about.__copyright__
author    = about.__author__

# The full version, including alpha/beta/rc tags
release = about.__version__


# -- General configuration ---------------------------------------------------

# If your documentation needs a minimal Sphinx version, state it here.
#
needs_sphinx = '3.4.3'

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.autosummary',
    'sphinx.ext.doctest',
    'sphinx.ext.intersphinx',
   #'sphinx.ext.todo',
   #'sphinx.ext.coverage',
    'sphinx.ext.ifconfig',
    'sphinx.ext.napoleon',
    'sphinx_tabs.tabs',
    'sphinxcontrib.spelling',
]

# Needed for e.g. linkcheck builder
tls_verify = False

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# The encoding of source files.
#
source_encoding = 'utf-8'

# The master toctree document.
master_doc = 'index'

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'sphinx'


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = 'bizstyle'  # 'alabaster'

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']


# -- Extension configuration -------------------------------------------------

# -- Options for autodoc extension -------------------------------------------

autoclass_content = 'both'
autodoc_member_order = 'bysource'

# -- Options for apidoc extension --------------------------------------------

apidoc_separate_modules = True
apidoc_module_first = True
apidoc_output_dir = 'api'

# -- Options for intersphinx extension ---------------------------------------

# Example configuration for intersphinx: refer to the Python standard library.
# intersphinx_mapping = {'https://docs.python.org/': None}

# -- Options for todo extension ----------------------------------------------

# If true, `todo` and `todoList` produce output, else they produce nothing.
todo_include_todos = False
