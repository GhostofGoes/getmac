============
Architecture
============

This page explains how getmac's code is organized, how a lookup flows through it, and a few of the design decisions behind it. It's for contributors, and for anyone who wants to know what getmac does on their system before using it. For how methods work in detail, see :doc:`module_api`, and for how to add one, see :doc:`adding_methods`.


Goals and constraints
=====================

getmac has one job: return the MAC address of a local network interface, or of a host on the local network, on as many platforms as possible, with nothing to install. That leads to a few constraints the design follows:

- **Pure Python, standard library only.** No runtime dependencies and no C-extensions, so getmac can be vendored or installed anywhere Python runs (CPython and PyPy, 3.9 and newer). Instead of calling platform APIs, it gets MACs the way a sysadmin would: by running commands like ``arp``, ``ip``, ``ifconfig`` and ``ipconfig.exe``, reading files like ``/proc/net/arp``, and parsing the output with regular expressions. A few methods use standard library features like :mod:`fcntl` and :mod:`ctypes`.
- **Many platforms, one interface.** Windows, Linux, macOS, WSL, the BSDs, Solaris, HP-UX, Android, Docker, and BusyBox all have different commands and files for the same information. The caller never sees the difference.
- **No privileges needed.** Everything getmac does works as a normal user, with one exception: some methods, such as ``arping``, need root. They're tried when they're installed, and if one is installed but doesn't have the privileges it needs, that lookup returns :obj:`None` (see :ref:`troubleshooting-privileges`).
- **Fail quietly, by default.** A lookup that can't find a MAC returns :obj:`None` and logs why. getmac only raises when something is wrong with how it was called, or when no method at all works on the platform (see :ref:`usage-errors`).

This replaced the pre-0.9.0 approach of throwing every method at the wall until one stuck, which was slow (a miss could take seconds), prone to false positives, and hard to test. The `rewrite summary <https://github.com/GhostofGoes/getmac/blob/main/docs/misc_docs/rewrite.md>`__ from the 0.9.0 release has the full story.


.. _architecture-where:

Where things live
=================

getmac is a small package with a handful of modules:

- ``getmac`` (``__init__.py``): the public API. :func:`~getmac.get_mac_address`, :func:`~getmac.get_default_interface`, ``settings``, and ``__version__`` are the names in ``__all__``. Nothing else is imported into the top-level package.
- :mod:`getmac.getmac`: the :class:`~getmac.getmac.Method` base class, every built-in method, the :data:`~getmac.getmac.METHODS` list, the :data:`~getmac.getmac.METHOD_CACHE` and :data:`~getmac.getmac.FALLBACK_CACHE` dicts, and lower-level functions such as :func:`~getmac.getmac.get_by_method` and :func:`~getmac.getmac.initialize_method_cache`.
- :mod:`getmac.variables`: the ``settings``, ``consts`` and ``gvars`` objects (see below), documented as the :class:`~getmac.variables.Settings`, :class:`~getmac.variables.Constants` and :class:`~getmac.variables.Variables` classes.
- :mod:`getmac.utils`: helper functions used by methods, such as :func:`~getmac.utils.popen` for running commands, :func:`~getmac.utils.search` for matching their output, and :func:`~getmac.utils.clean_mac` for normalizing a MAC.
- ``getmac.__main__``: the command line interface (:doc:`cli`), a thin ``argparse`` wrapper around :func:`~getmac.get_mac_address`.

``Method`` isn't exported from the top-level package, so import it with ``from getmac.getmac import Method``.


How a lookup works
==================

1. **Normalize the arguments.** :func:`~getmac.get_mac_address` accepts one of ``interface``, ``ip``, ``ip6``, or ``hostname``. :class:`bytes` are decoded as UTF-8, and :mod:`ipaddress` objects are converted to strings (an IPv6 object passed as ``ip`` is treated as ``ip6``, and a network raises :class:`ValueError`). ``localhost`` and ``127.0.0.1`` return ``00:00:00:00:00:00`` without doing anything else. A hostname is resolved to an IPv4 address with the system resolver.
2. **Refresh the ARP/NDP table, if asked.** Operating systems only know the MAC of a host they've talked to recently. For a remote host, when ``network_request`` is true (the default), getmac sends something to get the host into the table. For IPv4, on Linux it reads the ARP table file (:class:`~getmac.getmac.ArpFile`) first, and if the host is there, nothing is sent. If it isn't, getmac uses a method that makes a real ARP request (:class:`~getmac.getmac.CtypesHost` on Windows, or :class:`~getmac.getmac.ArpingHost`) if one is available, and only then falls back to sending one empty UDP packet to the host on ``settings.PORT`` (55555 by default), which makes the OS resolve the host and add it to its table. IPv6 goes straight to the UDP packet. :attr:`~getmac.variables.Settings.ARP_TIMEOUT` controls how long getmac keeps checking the table afterwards. With ``network_request=False``, getmac sends nothing and only reads what's already in the table. :ref:`module-api-ipv4-network` has the exact sequence.
3. **Pick a method.** Each way of getting a MAC is a :class:`~getmac.getmac.Method` subclass with a ``method_type`` (``ip4``, ``ip6``, ``ip`` for both, ``iface``, or ``default_iface``), the ``platforms`` it supports, and whether it sends network traffic. :func:`~getmac.getmac.initialize_method_cache` filters the ``METHODS`` registry by type and by the detected platform (or :attr:`~getmac.variables.Settings.OVERRIDE_PLATFORM`), creates each candidate, and calls its ``test()``, which is a cheap check such as "does this command exist" or "can this file be read". The first method that passes is cached for that type, and the others are kept as fallbacks. This happens once per method type per process, which is why the first call is slower than the rest.
4. **Run it, and fall back if it fails.** :func:`~getmac.getmac.get_by_method` calls the cached method's ``get(arg)``. If ``get()`` raises, or the method marks itself unusable, getmac logs the problem, drops the method, and tries the next fallback. If the last fallback fails too, the lookup returns :obj:`None`. A :class:`RuntimeError` comes from an earlier point: :func:`~getmac.getmac.initialize_method_cache` raises it when no method matches the type and platform, or when none of the matching methods pass ``test()``. That means the platform isn't supported, or something changed underneath getmac (see :ref:`usage-errors`).
5. **Clean the result.** Whatever the method found (a line of command output, the contents of a file, or a struct from a system call) goes through :func:`~getmac.utils.clean_mac`, which returns a lowercase colon-separated MAC, or :obj:`None` if the value isn't a valid MAC.

With no arguments, getmac finds the default interface first (step 3 with ``default_iface`` methods, which read the routing table), then looks up its MAC. If that interface has no MAC (a VPN tunnel, for example), the first interface with a MAC that isn't a loopback interface is used.


Three kinds of methods
======================

The ``METHODS`` list in ``getmac/getmac.py`` is the registry, and its order is the order of preference within each type. Methods come in three kinds:

- **Files.** On Linux and Android, ``/sys/class/net/<iface>/address`` gives an interface's MAC, ``/proc/net/arp`` is the ARP table, and ``/proc/net/route`` is the routing table. These are the fastest methods, so they're preferred where they exist.
- **System calls.** :mod:`fcntl` with ``SIOCGIFHWADDR`` on Linux, and :mod:`ctypes` calls into ``iphlpapi.dll`` on Windows. No subprocess, no parsing of text.
- **Commands.** ``ip``, ``arp``, ``ndp``, ``ifconfig``, ``netstat``, ``route``, ``arping``, ``lanscan``, ``networksetup``, ``getmac.exe``, ``ipconfig.exe``, ``netsh.exe``, and ``wmic.exe``. getmac runs the command with :func:`subprocess.check_output` (never through a shell), discards stderr, and searches stdout with a regular expression written for that command's output format. ``arping`` is tried when it's installed (``test()`` only checks that the command exists), so if it's installed but getmac doesn't have the privileges to use it (it usually needs root), the lookup returns :obj:`None` instead of falling back to the next method. See :ref:`troubleshooting-privileges`.

Each method is small and independent: it declares what it supports, checks whether it can run, and parses one format. A new platform or command version gets a new method and a new fixture of real command output in ``tests/samples/``, rather than a change to an existing method's regular expression. That keeps a fix for one platform from breaking another.


Platform detection and PATH
===========================

:class:`~getmac.variables.Constants` detects the platform once, at import time, from :func:`platform.uname`. :attr:`~getmac.variables.Constants.PLATFORM` is ``wsl`` on WSL1, ``linux`` on Linux, WSL2, and Android, and otherwise the lowercased system name (``darwin``, ``windows``, ``freebsd``, ``sunos``, and so on). Methods are filtered on it. ``other`` isn't something getmac detects, it's the bucket of generic methods getmac falls back to (with a :class:`RuntimeWarning`) when nothing matches. The names a method can list are in ``Method.VALID_PLATFORM_NAMES``: ``android``, ``darwin``, ``linux``, ``windows``, ``wsl``, ``openbsd``, ``freebsd``, ``netbsd``, ``dragonfly``, ``sunos``, ``hp-ux``, and ``other`` (see :ref:`module-api-platforms`). :attr:`~getmac.variables.Settings.OVERRIDE_PLATFORM` replaces the detected value, which is how the test suite exercises every platform's methods on one machine.

Commands are found on a search path (:attr:`gvars.PATH <getmac.variables.Variables.PATH>`) that's copied from the process's ``PATH`` at import time. On POSIX systems ``/sbin`` and ``/usr/sbin`` are added, since ``arp``, ``ip``, and ``ifconfig`` often live there and a normal user's ``PATH`` may not include them. On Windows, Python ``Scripts`` directories are removed, so a pip-installed ``getmac.exe`` (this package's own command) or ``ping.exe`` can't be picked instead of the Windows command of the same name. That only changes getmac's internal copy. Your shell's ``PATH`` isn't touched, which is why :doc:`troubleshooting` still tells you to add ``Scripts`` to it. Commands run with a copy of the environment that sets ``LC_ALL=C``, so their output isn't translated. See :ref:`usage-environment`.


Singleton classes for global state
==================================

All of getmac's global state lives in one module, :mod:`getmac.variables`, as attributes of three classes that are each instantiated exactly once:

- ``settings`` (:class:`~getmac.variables.Settings`): user-configurable options, such as :attr:`~getmac.variables.Settings.DEBUG` and :attr:`~getmac.variables.Settings.PORT`.
- ``consts`` (:class:`~getmac.variables.Constants`): platform detection results that don't change after import, such as :attr:`~getmac.variables.Constants.WINDOWS` and :attr:`~getmac.variables.Constants.PLATFORM`.
- ``gvars`` (:class:`~getmac.variables.Variables`): everything else that changes at runtime, such as :attr:`~getmac.variables.Variables.PATH` and :attr:`~getmac.variables.Variables.CHECK_COMMAND_CACHE`.

``getmac.py``, ``utils.py`` and ``__main__.py`` all import the same three objects (``from .variables import consts, gvars, settings``), so every module reads and writes one shared copy of each value, instead of each module keeping its own.

Why objects, instead of the module-level variables that 0.9.x used?

- **No** ``global`` **keyword.** Code changes an attribute (``gvars.DEFAULT_IFACE = ...``) instead of rebinding a module-level name, so functions don't need ``global`` declarations.
- **Changes are seen everywhere.** When you set ``settings.DEBUG = 2`` (or the CLI does, from ``--debug``), all of getmac sees it. A module-level variable copied with ``from ... import DEBUG`` would keep its old value in every module that imported it.
- **Tests are simpler.** One patch, such as ``mocker.patch.object(consts, "WINDOWS", True)``, changes the value everywhere it's used, and is undone automatically when the test ends.
- **Better docs.** Each attribute has a type annotation and a docstring, and the classes are rendered in the :doc:`api`, which makes it clear which values are settings for users to change and which are internal.
- **Room to grow.** An attribute can become a property that validates or lazily computes its value, and the singletons could later be replaced by instances passed to functions (as planned for :attr:`~getmac.variables.Settings.OVERRIDE_PLATFORM`), without changing the ``settings.NAME`` style of access in the code that uses them.
