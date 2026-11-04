"""Sphinx configuration file for getmac's documentation."""

import re
from datetime import datetime

import getmac


# -- Project information -----------------------------------------------------

project = 'getmac'
copyright = f'2017 - {datetime.now().year}, Christopher Goes'
author = 'Christopher Goes'
# The X.Y.Z version, and the full version including alpha/beta/rc tags
version = re.match(r'\d+\.\d+\.\d+', getmac.__version__).group()
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

# Warn about every reference that doesn't resolve. With -W, a broken
# reference fails the build.
nitpicky = True
nitpick_ignore = [
    # Private base class of the settings classes, not part of the documented API
    ("py:class", "getmac.variables.VarsClass"),
    # Added by sphinx-autodoc-typehints, and not in Python's inventory as data
    ("py:data", "typing.Union"),
]


# -- Options for the link checker (pdm run linkcheck) -----------------------

# GitHub adds heading anchors with JavaScript, so the checker can't see them
linkcheck_anchors_ignore_for_url = [r"https://github\.com/"]
linkcheck_ignore = [
    # Needs a GitHub login, so it redirects to the sign-in page
    r"https://github\.com/.*/issues/new",
    # Refuses automated requests (401)
    r"https://boxmatrix\.info/",
]
linkcheck_timeout = 30
linkcheck_retries = 2

# -- Options for HTML output -------------------------------------------------

html_theme = 'furo'
html_title = 'getmac documentation'
# The address the docs are published at, used for each page's canonical URL
html_baseurl = 'https://ghostofgoes.github.io/getmac/'

# Accessibility (WCAG 2.2). Each colour below is at least 7:1 against every
# background it's shown on (page, sidebar, code blocks, hover and highlight
# backgrounds), which meets 1.4.6 Contrast (Enhanced, AAA) and so 1.4.3 (AA) too.
html_theme_options = {
    # "View this page" and "Edit this page" link to the source on GitHub
    "source_repository": "https://github.com/GhostofGoes/getmac/",
    "source_branch": "main",
    "source_directory": "docs/",
    "footer_icons": [
        {
            "name": "GitHub",
            "url": "https://github.com/GhostofGoes/getmac",
            # GitHub's mark, from Furo's documentation
            "html": (
                '<svg stroke="currentColor" fill="currentColor" stroke-width="0" '
                'viewBox="0 0 16 16"><path fill-rule="evenodd" d="M8 0C3.58 0 0 3.58 0 '
                "8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-"
                "2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01"
                "-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1"
                ".07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08"
                "-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53"
                "-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3"
                ".07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 "
                '.21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z"></path></svg>'
            ),
            "class": "",
        },
    ],
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
