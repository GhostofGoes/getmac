#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
import sys

from getmac.getmac import __version__


with open('README.md') as f:  # Loads in the README for PyPI
    long_description = f.read()


setup(
    name='getmac',
    version=__version__,
    author='Christopher Goes',
    author_email='ghostofgoes@gmail.com',
    description='Get MAC addresses of remote hosts and local interfaces',
    long_description=long_description,  # This is what you see on PyPI page
    # PEP 566, PyPI Warehouse, setuptools>=38.6.0 make markdown possible
    long_description_content_type='text/markdown',
    url='https://github.com/GhostofGoes/getmac',
    download_url='https://pypi.org/project/getmac/',
    # project_urls={},  # TODO
    license='MIT',
    packages=find_packages(exclude=['tests.py']),
    zip_safe=True,
    entry_points={  # These enable commandline usage of the tool
        'console_scripts': [
            'getmac = getmac.__main__:main',
        ],
    },
    install_requires=['argparse'] if sys.version_info[:2] < (2, 7) else [],
    platforms=['any'],
    keywords='getmac get-mac macaddress mac-address mac address media access '
             'control ethernet networking network networks layer2 layer-2 osi '
             'ieee 802 mac-48 hardware-address tool script python python3',
    classifiers=[  # Used by PyPI to classify the project and make it searchable
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'License :: OSI Approved :: MIT License',

        'Operating System :: OS Independent',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'Operating System :: MacOS',

        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',

        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Programming Language :: Python :: Implementation :: IronPython',
        'Programming Language :: Python :: Implementation :: Jython',

        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',

        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Software Development :: Libraries',
        'Topic :: System :: Systems Administration',
        'Topic :: System :: Networking',
        'Topic :: Utilities',
    ]
)
