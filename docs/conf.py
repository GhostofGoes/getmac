"""Sphinx configuration file for getmac's documentation."""

from datetime import datetime

import getmac


# -- Project information -----------------------------------------------------

project = 'getmac'
copyright = '2017 - %i, Christopher Goes' % datetime.today().year
author = 'Christopher Goes'
version = getmac.__version__
release = getmac.__version__


# -- General configuration ---------------------------------------------------

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.viewcode',
    'sphinx.ext.intersphinx',
    'sphinx.ext.napoleon',  # Google and NumPy style docstrings
    'sphinx_autodoc_typehints',  # Type hints in docstrings
    'sphinx_inline_tabs',  # Adds directive: '.. tab:: <tab-name>'
    'sphinx_copybutton',  # Adds copy button to code blocks
    'sphinx_argparse_cli',  # Adds CLI documentation from argparse
    'sphinx_automodapi.automodapi',  # API documentation
    'sphinx_issues',  # GitHub Issues/PRs - :issue:, :pr:
]

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}


# -- Options for HTML output -------------------------------------------------

html_theme = 'furo'
# html_theme_options = {}


# -- Options for manual page output ------------------------------------------

# One entry per manual page. List of tuples
# (source start file, name, description, authors, manual section).
man_pages = [
    ('cli', 'getmac', 'Cross-platform Python package to get MAC addresses',
     [author], 1)
]


# -- Options for automodapi --------------------------------------------------

automodapi_inheritance_diagram = False


# -- Options for sphinx_issues -----------------------------------------------

issues_github_path = "ghostofgoes/getmac"
