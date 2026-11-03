===============
Troubleshooting
===============

This page covers the usual problems and what to do about them. For limitations that don't have a fix yet, see :ref:`platforms-known-issues`.

First, get the debug output
===========================

Before anything else, get the debug output. It shows which methods getmac tried, which commands it ran, and what they returned, which usually makes the problem obvious.

- On the command line: ``getmac -v -dddd [arguments]`` (see :doc:`cli`).
- In Python: configure logging and set ``settings.DEBUG = 4`` (see :ref:`usage-logging`).

Windows runs the wrong getmac
=============================

Windows has a system command with the same name, ``getmac.exe``, and depending on your ``PATH`` it may run instead of the ``getmac`` installed by pip. You'll know, because its output looks nothing like getmac's. Either:

- Add the ``\Scripts\`` folder of your Python installation to your user's ``PATH`` variable (for example, ``C:\Users\<USERNAME>\AppData\Local\Programs\Python\Python39\Scripts``, or ``C:\Users\<USERNAME>\scoop\apps\python\current\Scripts`` with scoop), or
- Run it via the Python interpreter: ``py -m getmac``. See :ref:`python-invoke`.

"getmac: command not found"
===========================

Your Python environment doesn't have the ``getmac`` command on the ``PATH``. Run it via the Python interpreter instead, e.g. ``python3 -m getmac``. See :ref:`python-invoke`.

.. _troubleshooting-remote-none:

None for a remote host
======================

getmac finds the MAC of a remote host in your system's ARP table (IPv4) or NDP table (IPv6). If the host isn't in there, you get :obj:`None`.

- Make sure the host is on your local network (the same layer 2 network, LAN, or VLAN). MACs aren't visible across routers, so ``getmac -4 8.8.8.8`` returning nothing is expected, not a bug.
- Make sure network requests are enabled (they are by default). Don't use ``--no-net`` or ``network_request=False`` unless you have to.
- The host may reply after getmac checks the table. Use ``--arp-timeout`` or :attr:`settings.ARP_TIMEOUT <getmac.variables.Settings.ARP_TIMEOUT>` to keep checking for a second or two. See :doc:`usage`.
- If ``arping`` is installed but getmac can't use it, you get :obj:`None` without a fallback. See :ref:`troubleshooting-privileges`.
- Check that the host is actually there, e.g. ``ping`` it, then try again. If it shows up in the table (``arp -a``, ``ip neigh``, etc.) but getmac still returns :obj:`None`, that's a bug (unless it's the ``arping`` problem above). Please `open a bug report <https://github.com/GhostofGoes/getmac/issues/new?template=1-bug-report.yml>`__ with the debug output.

None for a local IP address
===========================

On Linux and WSL, getmac can't get the MAC of an IP address that belongs to one of your own interfaces (e.g. ``getmac --ip 10.0.0.4`` when ``10.0.0.4`` is this machine). Other POSIX systems may have this issue too. Use the interface name instead, e.g. ``getmac -i eth0``.

This is one of the :ref:`known issues <platforms-known-issues>`.

None for an interface name
==========================

- Check the name against the real ones. ``ip link`` (Linux), ``ifconfig -a`` or ``ifconfig -l`` (macOS and the BSDs), ``networksetup -listallhardwareports`` (macOS), and ``dladm show-link`` (Solaris and illumos) list them. In Python, :func:`~getmac.get_default_interface` gives the name of the default one.
- Modern Linux doesn't name interfaces ``eth0`` anymore. Expect names like ``enp3s0``, ``ens33``, or ``wlp2s0``. On macOS, Wi-Fi is usually ``en0``.
- Names are case-sensitive on Unix.
- Tunnels (``utun0``, ``tun0``) and some virtual interfaces don't have a MAC, so :obj:`None` is expected. This is also why the default interface sometimes gives you a different interface's MAC (see :doc:`usage`).
- ``getmac -v -d`` shows the argument getmac tried, in case a shell or script changed it.

None for a Windows interface name
=================================

- The name has to match the whole connection name (``Ethernet 3``) or adapter description (``Intel(R) Ethernet Connection I217-V``). Case doesn't matter, but part of a name isn't enough. ``getmac.exe /V`` or ``ipconfig /all`` show the names.
- If ``getmac.exe`` doesn't work and getmac falls back to ``ipconfig.exe``, names are only found in English output, since Windows translates the adapter headers. Descriptions are found if the label is "Description" (English), and MACs are found in any language.

.. _troubleshooting-privileges:

Do I need root or admin?
========================

Mostly no. Looking up an interface, the default interface, or a host that's already in the ARP/NDP table works as a normal user. The exceptions:

- ``arping`` sends the ARP request, and it needs root (or ``CAP_NET_RAW``) on Linux and root on macOS. Debian's ``arping`` package sets that capability for you. If ``arping`` is installed but getmac can't use it, the lookup returns :obj:`None`, without falling back to another method or sending the UDP packet. Check with ``arping -c 1 <ip>`` and ``getmac -v -dddd``. To work around it, run as root, or give ``arping`` the capability (``setcap cap_net_raw+ep $(which arping)``), or ``ping`` the host first and use ``--no-net``, or use ``--force-method IpNeighborShow``.
- On Solaris and illumos, ``ifconfig`` only shows the MAC to root, but ``dladm`` (the method tried first) doesn't need it.
- Android restricts access to network information whatever user you are (see :ref:`platforms-android`).

This describes how getmac behaves today, and may change. :doc:`platforms` lists the commands behind each method.

Lookups are slow
================

- The first call is slower than the rest. getmac checks which methods work on your system the first time it needs one, and caches the result for the rest of the process.
- Lookups of hosts that don't reply take ``ARP_TIMEOUT`` seconds longer (it's ``0`` by default).
- Commands that getmac runs are stopped after 15 seconds (:attr:`~getmac.variables.Settings.COMMAND_TIMEOUT`) and the next method is tried. If a command is hanging, for example on DNS lookups, the debug output shows which one. Lower the timeout, or open an issue so a faster command can be used.

RuntimeError: no methods
========================

getmac raises a :class:`RuntimeError` when there are no methods that match the type of lookup and your platform, or all of them failed their test (i.e. the commands they need aren't installed). This should almost never happen unless you're on an exotic platform or have an unusual configuration, or a platform update changed the commands getmac uses.

1. Get the debug output. Level 2 (``-dd``) shows which methods were considered, and which failed their test.
2. Check that the commands for your platform are installed. :doc:`platforms` lists them. getmac looks for commands on your ``PATH`` plus ``/sbin`` and ``/usr/sbin`` (see :ref:`usage-environment`).
3. `Open a bug report <https://github.com/GhostofGoes/getmac/issues/new?template=1-bug-report.yml>`__ with the debug output, so getmac can be fixed for your platform.

Android finds nothing
=====================

Newer versions of Android don't have many of the commands getmac uses, and restrict access to network information. See :ref:`platforms-android`.

Docker sees the wrong interfaces
================================

By default, a container only sees its own network, not the host's. See :doc:`docker`.

Reporting a problem
===================

If none of this helps, run ``getmac -v -dddd [arguments]`` and save the output. Redact any MACs, IPs, or hostnames you don't want to be public. Then search the `existing issues <https://github.com/GhostofGoes/getmac/issues>`__, and if yours isn't there, `open a bug report <https://github.com/GhostofGoes/getmac/issues/new?template=1-bug-report.yml>`__ and paste the output in. The form asks for the rest (your platform, Python version, and getmac version).

If it's a potential security vulnerability, do *not* open an issue! Follow the steps in :doc:`security` instead.
