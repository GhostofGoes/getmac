======
getmac
======

getmac is a pure-Python package to get the MAC addresses of network interfaces and hosts on the local network.

It provides a platform-independent interface to get the MAC addresses of:

- System network interfaces (by interface name)
- Remote hosts on the local network (by IPv4/IPv6 address or hostname)

It provides a Python function, :func:`~getmac.get_mac_address`, and a command-line interface, :ref:`getmac <args>`.

Features
========

- Pure-Python (no compiled C-extensions required!)
- Python 3.9+, on CPython and `PyPy <https://www.pypy.org/>`__
- Lightweight, with no dependencies and a relatively small package size
- Supports most platforms: Windows, Linux, macOS, the BSDs, Solaris and illumos, HP-UX, Android, WSL, and Docker (see :doc:`platforms`)
- Provides a simple command line tool
- MIT licensed!

Quick start
===========

Install it:

.. code-block:: shell

   python3 -m pip install getmac

Use it from Python:

.. code-block:: python

   from getmac import get_mac_address

   get_mac_address()                        # The default interface
   get_mac_address(interface="eth0")        # A local interface, by name
   get_mac_address(ip="192.168.0.1")        # A host on the LAN, by IPv4 address
   get_mac_address(ip6="fe80::1")           # ...by IPv6 address
   get_mac_address(hostname="home.router")  # ...or by hostname

Or from the terminal:

.. code-block:: shell

   getmac
   getmac -i eth0
   getmac -4 192.168.0.1
   getmac -6 fe80::1
   getmac -n home.router

The result is a lowercase, colon-separated MAC address (e.g. ``'00:11:22:33:44:55'``). If nothing was found, it's :obj:`None` (on the command line, nothing is printed and the exit code is ``1``).

Where to go next
================

Getting started
   :doc:`installation` has every way to install getmac, and :doc:`upgrading` covers what changed from 0.9.x.

Using getmac
   :doc:`usage` is the guide to the Python API and its settings. :doc:`cli` is the guide to the ``getmac`` command, and :doc:`docker` covers the Docker image.

When something goes wrong
   :doc:`troubleshooting` has fixes for common problems. :doc:`platforms` lists what's supported, and which commands getmac uses on each platform. :doc:`glossary` defines the terms used in these docs.

Reference
   :doc:`api` is the full API reference, generated from the code. :doc:`module_api` explains how getmac picks a method, and :doc:`custom_methods` covers adding, removing, or forcing methods at runtime.

Contributing
   :doc:`contributing` is the contribution guide, including how to set up a development environment. :doc:`samples` explains how to collect the command output the tests use, :doc:`adding_methods` walks through adding support for a new command or platform, and :doc:`architecture` explains how the code is organized.

.. toctree::
   :hidden:
   :titlesonly:
   :caption: Getting started

   installation
   upgrading

.. toctree::
   :hidden:
   :titlesonly:
   :caption: Using getmac

   usage
   cli
   docker
   troubleshooting
   platforms
   glossary

.. toctree::
   :hidden:
   :titlesonly:
   :caption: Reference

   api
   module_api
   custom_methods

.. toctree::
   :hidden:
   :titlesonly:
   :caption: Contributing

   contributing
   samples
   adding_methods
   architecture

.. toctree::
   :hidden:
   :titlesonly:
   :caption: Project

   changelog
   security
   code_of_conduct
