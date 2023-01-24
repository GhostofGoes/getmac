#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from io import open  # Python 2 compatibility

from setuptools import setup

from getmac.getmac import __version__


# Build the page that will be displayed on PyPI from the README and CHANGELOG
with open("README.md", encoding="utf-8") as f:
    long_description = f.read()
long_description += "\n\n"
with open("CHANGELOG.md", encoding="utf-8") as f:
    long_description += f.read()


setup(
    name="getmac",
    version=__version__,
    author="Christopher Goes",
    author_email="ghostofgoes@gmail.com",
    description="Get MAC addresses of remote hosts and local interfaces",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/GhostofGoes/getmac",
    project_urls={
        # "Documentation": "https://getmac.readthedocs.io/en/latest/",
        "Changelog": "https://github.com/GhostofGoes/getmac/blob/main/CHANGELOG.md",
        "Issue tracker": "https://github.com/GhostofGoes/getmac/issues",
        "Source": "https://github.com/GhostofGoes/getmac",
        "Discord server": "https://discord.gg/python",
    },
    license="MIT",
    data_files=[],
    packages=["getmac"],
    zip_safe=True,
    entry_points={"console_scripts": ["getmac2 = getmac.__main__:main"]}
    if sys.version_info[:2] <= (2, 7)
    else {"console_scripts": ["getmac = getmac.__main__:main"]},
    install_requires=[],
    python_requires=">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*",
    keywords=[
        "getmac",
        "get-mac",
        "macaddress",
        "mac-address",
        "mac",
        "ethernet",
        "mac-48",
        "networking",
        "network",
        "networking",
        "layer2",
        "layer-2",
        "802.3",
    ],
    classifiers=[  # TODO(python3): update classifiers
        # TODO(1.0.0): change to 5 - Production/Stable
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX",
        "Operating System :: MacOS",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Programming Language :: Python :: Implementation :: IronPython",
        "Programming Language :: Python :: Implementation :: Jython",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Software Development :: Libraries",
        "Topic :: System :: Systems Administration",
        "Topic :: System :: Networking",
        "Topic :: Utilities",
    ],
)
