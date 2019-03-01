# -*- coding: utf-8 -*-
#
# Configuration file for the Sphinx documentation builder.
#
# This file does only contain a selection of the most common options. For a
# full list see the documentation:
# http://www.sphinx-doc.org/en/master/config

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
import os
import sys
DOCDIR = os.path.pardir(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.pardir(DOCDIR), 'getmac'))

from recommonmark.transform import AutoStructify  # noqa: E402

import getmac  # noqa: E402


# -- Project information -----------------------------------------------------

project = 'getmac'
copyright = '2019, Christopher Goes'
author = 'Christopher Goes'
version = getmac.__version__
release = getmac.__version__


# -- General configuration ---------------------------------------------------

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.viewcode',
]

source_parsers = {
    '.md': 'recommonmark.parser.CommonMarkParser',
}

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# The suffix(es) of source filenames.
source_suffix = ['.md']  # , '.rst'

# The master toctree document.
master_doc = 'index'

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = []

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'sphinx'  # None


# -- Options for HTML output -------------------------------------------------

html_theme = 'sphinx_rtd_theme'
# html_theme_options = {}

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = []  # '_static'

# Custom sidebar templates, must be a dictionary that maps document names
# to template names.
#
# The default sidebars (for documents that don't match any pattern) are
# defined by theme itself.  Builtin themes are using these templates by
# default: ``['localtoc.html', 'relations.html', 'sourcelink.html',
# 'searchbox.html']``.
#
html_sidebars = {
    '**': [
        'relations.html',  # needs 'show_related': True theme option to display
        'searchbox.html',
    ]
}

html_context = {
    "display_github": True,  # Integrate GitHub
    "github_user": "GhostofGoes",  # Username
    "github_repo": "getmac",  # Repo name
    "github_version": "master",  # Version
    "conf_py_path": "/",  # Path in the checkout to the docs root
}


# -- Options for manual page output ------------------------------------------

# One entry per manual page. List of tuples
# (source start file, name, description, authors, manual section).
man_pages = [
    (master_doc, 'getmac', 'Cross-platform Python package to get MAC addresses',
     [author], 1)
]


# -- Extension configuration -------------------------------------------------

def setup(app):
    app.add_config_value('recommonmark_config', {
        'auto_toc_tree_section': 'Contents',
        'enable_eval_rst': True,
        'enable_auto_doc_ref': True,
    }, True)
    app.add_transform(AutoStructify)
