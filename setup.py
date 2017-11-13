#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Source: https://github.com/GhostofGoes/ADLES/blob/master/setup.py

from setuptools import setup, find_packages
from get_mac.getmac import __version__


with open('README.rst') as f:  # Loads in the README for PyPI
    long_description = f.read()


setup(
    name='get-mac',
    version=__version__,
    author="Christopher Goes",
    author_email="goesc@acm.org",
    description='Cross-platform Pure-Python 2/3 tool '
                'to get a gosh-darn MAC address.',
    long_description=long_description,  # This is what you see on PyPI page
    url="https://github.com/GhostofGoes/get-mac",
    download_url='https://pypi.python.org/pypi/get-mac',
    license="MIT",
    packages=find_packages(exclude=["tests.py"]),
    zip_safe=True,
    entry_points={  # These enable commandline usage of the tool
        'console_scripts': [
            'get-mac = get_mac.getmac:_get_mac_main'
        ]
    },
    platforms=["any"],
    keywords="get-mac mac-address mac address networking networks layer2 "
             "media access control ieee 802 mac-48 ethernet lol",
    classifiers=[  # Used by PyPI to classify the project and make it searchable
        'Development Status :: 2 - Pre-Alpha',
        'Environment :: Console',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 2.6',
        'Operating System :: OS Independent',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'Topic :: System :: Systems Administration',
        'Topic :: Software Development :: Libraries',
        'Topic :: System :: Networking',
        'Topic :: Utilities'
    ]
)
