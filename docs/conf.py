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

# Accessibility (WCAG 2.2). Each colour below is at least 7:1 against every
# background it's shown on (page, sidebar, code blocks, hover and highlight
# backgrounds), which meets 1.4.6 Contrast (Enhanced, AAA) and so 1.4.3 (AA) too.
html_theme_options = {
    "light_css_variables": {
        # Links, sidebar top-level links, current TOC item, selected tab
        "color-brand-primary": "#1a42a3",
        "color-brand-content": "#1a42a3",
        "color-brand-visited": "#6a1fb8",
        # TOC items, footer, sidebar links, signature punctuation
        "color-foreground-secondary": "#45474d",
        # Sidebar captions, "On this page", Next/Previous, inactive tab labels
        "color-foreground-muted": "#4b4e55",
        # API object names (Furo's #b30000 is 6.28:1 on the signature hover background)
        "color-problematic": "#9e0000",
        # Code block background: a light grey that keeps every token in the
        # a11y-high-contrast-light style at 7:1 or more (lowest is 7.02:1)
        "color-code-background": "#f8f8f8",
        # 1.4.1 Use of Color: a link underline that's visible against the page
        "color-link-underline": "#6c7fb8",
        "color-link-underline--visited": "#9a78c8",
    },
    "dark_css_variables": {
        "color-brand-primary": "#8cc1ff",
        "color-brand-content": "#8cc1ff",
        "color-brand-visited": "#c79bff",
        "color-foreground-secondary": "#b4b8bd",
        "color-foreground-muted": "#b4b8bd",
        "color-problematic": "#ff8f8f",
        # Background behind a linked-to heading or term, and behind search terms
        "color-highlight-on-target": "#24240a",
        "color-highlighted-background": "#0a2440",
        # 1.4.1 Use of Color: Furo's dark underline (#303335) is 1.45:1 on the page
        "color-link-underline": "#5f7fa8",
        "color-link-underline--visited": "#8a6fae",
    },
}

# 1.4.6 Contrast (Enhanced): every token in these styles is at least 7:1 on its background
pygments_style = "a11y-high-contrast-light"
pygments_dark_style = "a11y-high-contrast-dark"

html_static_path = ["_static"]
html_css_files = ["a11y.css"]


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
