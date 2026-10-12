===============
Troubleshooting
===============

This page lists the usual problems with getmac, and what to do about them. For the limitations that have no fix yet, see the known issues in :doc:`usage`.

Get debug output
================

Before you do other steps, get the debug output. It shows the methods that getmac tries, the commands that it runs, and their output.

- On the command line, use ``getmac -v -dddd [arguments]``. See :doc:`cli`.
- In Python, configure logging and set :attr:`settings.DEBUG <getmac.variables.Settings.DEBUG>`. See :ref:`module-api-logging`.

Windows runs the wrong getmac command
=====================================

Windows has a system command with the same name, ``getmac.exe``. Windows can run it instead of the ``getmac`` command that ``pip`` installs.

To fix this, do one of these steps:

- Add the ``\Scripts\`` folder of your Python installation to the ``PATH`` variable of your user.
- Start getmac with the Python interpreter, for example ``py -m getmac``. See :ref:`python-invoke`.

The getmac command is not found
===============================

Your Python environment may not put the ``getmac`` command on the ``PATH``. Start getmac with the Python interpreter instead, for example ``python3 -m getmac``. See :ref:`python-invoke`.

The result is None for a remote host
====================================

getmac finds the MAC address of a remote host in the ARP table (IPv4) or the NDP table (IPv6) of your system. If the host is not in the table, the result is :obj:`None`.

- Make sure that the host is on your local network (the same layer 2 network). getmac cannot get the MAC address of a host outside your LAN.
- Make sure that network requests are enabled. They are enabled by default. Do not use ``--no-network-requests`` or ``network_request=False``.
- The host can reply after getmac checks the table. Use ``--arp-timeout`` or :attr:`settings.ARP_TIMEOUT <getmac.variables.Settings.ARP_TIMEOUT>` to check the table again for a number of seconds. See :doc:`usage`.

The result is None for a local IP address
=========================================

On Linux and WSL, getmac cannot get the MAC address of the IP address of a local interface. Other POSIX systems may have this issue also. Use the interface name instead, for example ``getmac -i eth0``.

The result is None for a Windows interface name
===============================================

- On Windows, the interface name must be the same as the full name or the full description of the interface. Case is not important.
- If getmac uses ``ipconfig.exe``, getmac finds interfaces by name only when the output is in English.

RuntimeError
============

getmac raises a :class:`RuntimeError` when it can use no method for the lookup. This occurs on unusual platforms or configurations, or after a platform update changes the commands that getmac uses.

1. Get the debug output. It shows the methods that getmac tested, and the methods that failed.
2. Make sure that the commands for your platform are installed. :doc:`platforms` lists them.
3. Report the issue on `GitHub <https://github.com/GhostofGoes/getmac/issues>`__, with the debug output.

Android finds nothing
=====================

Newer versions of Android do not have many of the commands that getmac uses. See :ref:`platforms-android`.

Docker shows the wrong interfaces
=================================

By default, a container sees only its own network. See the network section of :doc:`docker`.

Report a problem
================

If these steps do not fix the problem, please open an `issue on GitHub <https://github.com/GhostofGoes/getmac/issues>`__. Include:

- The debug output from ``getmac -v -dddd [arguments]``. Replace MAC addresses, IP addresses and hostnames that you do not want to make public.
- Your platform and its version.
- Your Python version and your getmac version (``getmac --version``).

For security issues, do not open a public issue. Follow the steps in :doc:`security`.
