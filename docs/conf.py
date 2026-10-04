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
    'myst_parser',  # Markdown support
]

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}

# Developer notes (TODO list, release steps, etc.) aren't part of the published docs
exclude_patterns = ["misc_docs"]

# Generate anchors for Markdown headings, so links like "#ai-policy" work
myst_heading_anchors = 3


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


def _tabs_to_paragraphs(app, doctree, docname):
    """
    The manpage writer doesn't support the labels of tabs from sphinx_inline_tabs.
    For manpages, replace each tab's label with a bold paragraph instead.
    """
    if app.builder.format != "man":
        return

    from docutils import nodes
    from sphinx_inline_tabs._impl import TabContainer

    for label in list(doctree.findall(nodes.label)):
        if isinstance(label.parent, TabContainer):
            label.replace_self(nodes.paragraph("", "", nodes.strong(text=f"{label.astext()}:")))


def setup(app):
    app.connect("doctree-resolved", _tabs_to_paragraphs)


# -- Options for automodapi --------------------------------------------------

automodapi_inheritance_diagram = False


# -- Options for sphinx_issues -----------------------------------------------

issues_github_path = "ghostofgoes/getmac"
