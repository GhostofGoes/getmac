#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
from getmac.getmac import __version__


with open('README.md') as f:  # Loads in the README for PyPI
    long_description = f.read()


setup(
    name='get-mac',
    version=__version__,
    author="Christopher Goes",
    author_email="goesc@acm.org",
    description='Python interface to get the MAC address '
                'of remote hosts or network interfaces.',
    long_description=long_description,  # This is what you see on PyPI page
    # PEP 566, PyPI Warehouse, setuptools>=38.6.0 make markdown possible
    long_description_content_type='text/markdown',
    url="https://github.com/GhostofGoes/get-mac",
    download_url='https://pypi.org/project/get-mac/',
    license="MIT",
    packages=find_packages(exclude=["tests.py"]),
    zip_safe=True,
    entry_points={  # These enable commandline usage of the tool
        'console_scripts': [
            'get-mac = getmac.__main__:main'
        ]
    },
    platforms=["any"],
    keywords="get-mac getmac mac-address mac address networking networks layer2 osi "
             "media access control ieee 802 mac-48 ethernet network python layer-2",
    classifiers=[  # Used by PyPI to classify the project and make it searchable
        'Development Status :: 2 - Pre-Alpha',
        'Environment :: Console',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
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
