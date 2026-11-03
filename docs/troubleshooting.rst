===============
Troubleshooting
===============

This page covers the usual problems and what to do about them. For limitations that don't have a fix yet, see :ref:`platforms-known-issues`.

First, get the debug output
===========================

Before anything else, get the debug output. It shows which methods getmac tried, which commands it ran, and what they returned, which usually makes the problem obvious.

- On the command line: ``getmac -v -dddd [arguments]`` (see :doc:`cli`).
- In Python: configure logging and set ``settings.DEBUG = 4`` (see :doc:`usage`).

Windows runs the wrong getmac
=============================

Windows has a system command with the same name, ``getmac.exe``, and depending on your ``PATH`` it may run instead of the ``getmac`` installed by pip. You'll know, because its output looks nothing like getmac's. Either:

- Add the ``\Scripts\`` folder of your Python installation to your user's ``PATH`` variable, or
- Run it via the Python interpreter: ``py -m getmac``. See :ref:`python-invoke`.

"getmac: command not found"
===========================

Your Python environment doesn't have the ``getmac`` command on the ``PATH``. Run it via the Python interpreter instead, e.g. ``python3 -m getmac``. See :ref:`python-invoke`.

None for a remote host
======================

getmac finds the MAC of a remote host in your system's ARP table (IPv4) or NDP table (IPv6). If the host isn't in there, you get :obj:`None`.

- Make sure the host is on your local network (the same layer 2 network, LAN, or VLAN). MACs aren't visible across routers, so ``getmac -4 8.8.8.8`` returning nothing is expected, not a bug.
- Make sure network requests are enabled (they are by default). Don't use ``--no-net`` or ``network_request=False`` unless you have to.
- The host may reply after getmac checks the table. Use ``--arp-timeout`` or :attr:`settings.ARP_TIMEOUT <getmac.variables.Settings.ARP_TIMEOUT>` to keep checking for a second or two. See :doc:`usage`.
- Check that the host is actually there, e.g. ``ping`` it, then try again. If it shows up in the table (``arp -a``, ``ip neigh``, etc.) but getmac still returns :obj:`None`, that's a bug. Please report it with the debug output.

None for a local IP address
===========================

On Linux and WSL, getmac can't get the MAC of an IP address that belongs to one of your own interfaces (e.g. ``getmac --ip 10.0.0.4`` when ``10.0.0.4`` is this machine). Other POSIX systems may have this issue too. Use the interface name instead, e.g. ``getmac -i eth0``.

None for a Windows interface name
=================================

- The name has to match the whole connection name (``Ethernet 3``) or adapter description (``Intel(R) Ethernet Connection I217-V``). Case doesn't matter, but part of a name isn't enough. ``getmac.exe /V`` or ``ipconfig /all`` show the names.
- If ``getmac.exe`` doesn't work and getmac falls back to ``ipconfig.exe``, names are only found in English output, since Windows translates the adapter headers. Descriptions are found in any language.

Lookups are slow
================

- The first call is slower than the rest. getmac checks which methods work on your system the first time it needs one, and caches the result for the rest of the process.
- Lookups of hosts that don't reply take ``ARP_TIMEOUT`` seconds longer (it's ``0`` by default).
- Commands that getmac runs are stopped after 15 seconds (:attr:`~getmac.variables.Settings.COMMAND_TIMEOUT`) and the next method is tried. If a command is hanging, for example on DNS lookups, the debug output shows which one. Lower the timeout, or open an issue so a faster command can be used.

RuntimeError: no methods
========================

getmac raises a :class:`RuntimeError` when there are no methods that match the type of lookup and your platform, or all of them failed their test (i.e. the commands they need aren't installed). This should almost never happen unless you're on an exotic platform or have an unusual configuration, or a platform update changed the commands getmac uses.

1. Get the debug output. Level 2 (``-dd``) shows which methods were considered, and which failed their test.
2. Check that the commands for your platform are installed. :doc:`platforms` lists them.
3. Report it on `GitHub <https://github.com/GhostofGoes/getmac/issues>`__ with the debug output, so getmac can be fixed for your platform.

Android finds nothing
=====================

Newer versions of Android don't have many of the commands getmac uses, and restrict access to network information. See :ref:`platforms-android`.

Docker sees the wrong interfaces
================================

By default, a container only sees its own network, not the host's. See :doc:`docker`.

Reporting a problem
===================

If none of this helps, please `open an issue on GitHub <https://github.com/GhostofGoes/getmac/issues>`__, and include:

- The debug output from ``getmac -v -dddd [arguments]``. Redact any MACs, IPs, or hostnames you don't want to be public.
- Your platform and its version (e.g. "Ubuntu 24.04", "Windows 11", "macOS 15").
- Your Python version, and your getmac version (``getmac --version``).
- What you expected to happen, and what happened instead.

If it's a potential security vulnerability, do *not* open an issue! Follow the steps in :doc:`security` instead.
