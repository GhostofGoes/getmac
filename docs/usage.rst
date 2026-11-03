=====
Usage
=====

getmac provides a Python function, :func:`~getmac.get_mac_address`, and a command-line interface, :ref:`getmac <args>`. This page covers using getmac from Python as a library. The command-line interface is documented in :doc:`cli`.

If a MAC address was found, :func:`~getmac.get_mac_address` returns it as a lowercase, colon-separated string, e.g. ``'00:11:22:33:44:55'``. If no MAC was found, :obj:`None` is returned. See :ref:`usage-errors` for the exceptions it can raise.

Examples
========

Here's the basic idea. With no arguments, you get the MAC of the default network interface. Pass the name of an interface to get its MAC, or the address of a host on your network to get that host's:

.. code-block:: pycon

   >>> from getmac import get_mac_address
   >>> get_mac_address()
   '00:11:22:33:44:55'
   >>> get_mac_address(interface="eth0")
   '00:11:22:33:44:55'
   >>> get_mac_address(ip="192.168.0.1")
   '66:77:88:99:aa:bb'

Only one of ``interface``, ``ip``, ``ip6``, and ``hostname`` can be used at a time.


Default interface
-----------------

With no arguments, you get the MAC of the system's default network interface, i.e. the one with the default route:

.. code-block:: python

   from getmac import get_mac_address

   get_mac_address()

If the default interface can't be determined (for example, if there aren't any routes) or doesn't have a MAC (for example, a VPN tunnel), then the first interface that has a MAC and isn't a loopback interface is used. If there isn't one, :obj:`None` is returned. On Windows, only the default interface is used, and with network requests enabled, getmac first looks up the IP of the default interface as a host (see :ref:`platforms-windows`).

To get the *name* of the default interface, use :func:`~getmac.get_default_interface`. It finds the default interface without the fallbacks that :func:`~getmac.get_mac_address` applies later (the first interface with a MAC, the Windows host lookup, and the remembered default), so the MAC from :func:`~getmac.get_mac_address` can belong to a different interface than the name you get here. See :ref:`how the default interface is found <module-api-get-default-interface>`.

.. code-block:: python

   from getmac import get_default_interface

   print(get_default_interface())  # e.g. "eth0", or "Ethernet 2" on Windows


Interface names
---------------

.. code-block:: python

   from getmac import get_mac_address

   # Linux example
   get_mac_address(interface="eth0")

   # Windows example
   get_mac_address(interface="Ethernet 3")

On Windows, the name must match the whole connection name (``Ethernet 3``) or adapter description (``Intel(R) Ethernet Connection I217-V``). Case doesn't matter. On Unix, names are case-sensitive, and an interface that doesn't exist (or doesn't have a MAC, like a tunnel) gives you :obj:`None`.


.. _usage-remote-hosts:

Remote hosts: IP addresses and hostnames
----------------------------------------

"Remote hosts" are hosts in *your local layer 2 network*, also known as a "broadcast domain", "LAN", or "VLAN". As far as I know, there is not a reliable method to get a MAC address for a remote host external to the LAN, since MACs don't cross routers. If you know any methods otherwise, please `open an issue on GitHub <https://github.com/GhostofGoes/getmac/issues>`_ or shoot me an email, I'd love to be wrong about this.

.. code-block:: python

   from getmac import get_mac_address

   # IPv4 example
   get_mac_address(ip="192.168.0.1")

   # IPv6 example
   get_mac_address(ip6="fe80::1")

   # Hostname example
   get_mac_address(hostname="home.router")

A hostname is resolved to an IPv4 address with DNS, then looked up like ``ip``. ``hostname="localhost"`` (``-n localhost`` on the command line) and ``ip="127.0.0.1"`` (``-4 127.0.0.1``) return ``"00:00:00:00:00:00"``, the MAC of the loopback interface, without looking anything up. Other spellings, such as ``::1``, ``127.0.0.2``, ``LOCALHOST``, or the host's own name, aren't short-circuited, and return :obj:`None`.

Finding the MAC of a remote host means finding it in the system's ARP table (IPv4) or NDP table (IPv6). The host is only in the table if the system has talked to it recently, so by default (``network_request=True``) getmac tries to get it in there first:

1. On Linux, getmac reads the ARP table file first. If it has a complete entry for the host, nothing is sent on the network.
2. If it doesn't, then on Windows, or on Linux and macOS with ``arping`` installed, getmac sends an ARP request to the host and waits for the reply (IPv4 only).
3. If neither applies, getmac sends an empty UDP packet to the host on port ``55555`` (:attr:`~getmac.variables.Settings.PORT`). To send the packet, the system has to resolve the host's MAC with ARP (or NDP), which adds it to the table. IPv6 hosts always use this step.

Reading the tables doesn't need special privileges, but ``arping`` usually does (root, or ``CAP_NET_RAW``). If it's installed and getmac can't use it, the lookup returns :obj:`None`. See :ref:`troubleshooting-privileges`.

Set ``network_request=False`` to only use what's already in the table, for example if you have requirements to prevent network traffic:

.. code-block:: python

   from getmac import get_mac_address

   get_mac_address(ip="10.0.0.1", network_request=False)

The host's entry is only added to the table once it replies, which can take longer than getmac takes to check the table. To keep checking for it for up to a number of seconds, set :attr:`~getmac.variables.Settings.ARP_TIMEOUT` (``--arp-timeout`` on the command line). Lookups of hosts that don't reply take this much longer. This doesn't apply when getmac sends an ARP request itself, since it waits for the reply.

.. code-block:: python

   from getmac import get_mac_address, settings

   settings.ARP_TIMEOUT = 1.0  # Default is 0, check once
   get_mac_address(ip="10.0.0.1")

What ``network_request`` does depends on the argument. With ``interface``, nothing, so it's safe to set in a script. With ``ip``, ``ip6``, and ``hostname``, it allows the ARP request or UDP packet above. With no arguments, it only matters on Windows, where it allows connecting the UDP socket to find the default interface's IP. :ref:`module-api-ipv4-network` has the exact sequence of what getmac does.

IPv6 link-local addresses (``fe80::/10``) only mean something together with an interface, so they can carry a zone: the interface's name (``ip6="fe80::1%en0"``) or its index (``ip6="fe80::1%2"``). On macOS and the BSDs (:class:`~getmac.getmac.NdpNeighbors`) and Solaris and illumos (:class:`~getmac.getmac.NetstatNetToMedia`), getmac uses the zone to pick the right entry when the same address is on more than one link. On Linux and Windows, pass the address without a zone, since ``ip neighbor show`` and ``netsh`` don't understand it today.

If a remote host gives you :obj:`None` and you think it shouldn't, see :ref:`troubleshooting-remote-none`.


Using ipaddress objects
-----------------------

The ``ip`` and ``ip6`` arguments also accept objects from the standard library's :mod:`ipaddress` module:

- ``ip`` accepts :class:`~ipaddress.IPv4Address` and :class:`~ipaddress.IPv4Interface` objects.
- ``ip`` also accepts :class:`~ipaddress.IPv6Address` and :class:`~ipaddress.IPv6Interface` objects, and treats them as IPv6 addresses, as if ``ip6`` was used. A *string* passed to ``ip`` is always treated as IPv4.
- ``ip6`` accepts :class:`~ipaddress.IPv6Address` and :class:`~ipaddress.IPv6Interface` objects.
- Networks, such as :class:`~ipaddress.IPv4Network`, raise a :class:`ValueError`. They're networks, not hosts, and passing them makes no sense.

.. code-block:: python

   from getmac import get_mac_address
   from ipaddress import ip_address, IPv4Interface, IPv6Interface

   ipv4_addr = ip_address("192.168.0.1")
   print(get_mac_address(ip=ipv4_addr))

   ipv6_addr = ip_address("fe80::1")
   print(get_mac_address(ip=ipv6_addr))

   ipv4_iface = IPv4Interface("192.168.0.1/24")
   print(get_mac_address(ip=ipv4_iface))

   ipv6_iface = IPv6Interface("fe80::1/64")
   print(get_mac_address(ip=ipv6_iface))

All four lookup arguments also accept :class:`bytes`, which are decoded as UTF-8.


.. _configuration:

Configuration
=============

Settings that affect the behavior of getmac are attributes of ``getmac.settings`` (an instance of :class:`~getmac.variables.Settings`, which documents each one in full). Set them before calling :func:`~getmac.get_mac_address`. Logging is the exception, it's handled by Python's :mod:`logging` module (see :ref:`usage-logging`). The following settings are available, each with its command-line flag:

- :attr:`~getmac.variables.Settings.DEBUG`: integer that controls debugging output. The higher the value, the more output you get (``0`` is the default, ``4`` is roughly the highest). Command line: ``-d``, repeated once per level.
- :attr:`~getmac.variables.Settings.PORT`: the UDP port used to populate the ARP table (IPv4) or NDP table (IPv6) when looking up MACs for hosts or IPs. Default is ``55555``. Command line: ``--override-port``.
- :attr:`~getmac.variables.Settings.ARP_TIMEOUT`: how long to keep checking the ARP table (IPv4) or NDP table (IPv6) for a host after sending the UDP packet, in seconds. ``0`` (the default) checks once, without waiting. Command line: ``--arp-timeout``.
- :attr:`~getmac.variables.Settings.COMMAND_TIMEOUT`: how long to wait for a command that getmac runs (such as ``arp`` or ``ipconfig.exe``) to finish, in seconds. A command that takes longer is stopped, and the next method is tried. The default is 15 seconds, and :obj:`None` or ``0`` waits for as long as the command takes. There's no command-line flag.
- :attr:`~getmac.variables.Settings.OVERRIDE_PLATFORM`: override the platform detection with the given value (e.g. ``"linux"``, ``"windows"``, ``"freebsd"``, etc). Any value returned by :func:`platform.system` is valid. Set it before the first lookup. Command line: ``--override-platform``.
- :attr:`~getmac.variables.Settings.FORCE_METHOD`: name of a method to use for every lookup, e.g. ``"IpNeighborShow"`` for :class:`~getmac.getmac.IpNeighborShow`. It's used regardless of its method type or platform compatibility, and :func:`~getmac.getmac.Method.test` is NOT checked! The list of available methods is in :data:`getmac.getmac.METHODS` and the :doc:`api`. Command line: ``--force-method``.

The last two are for debugging and testing. :doc:`module_api` explains how they interact with method selection.

Here's an example of changing some settings at runtime:

.. code-block:: python

   from getmac import get_mac_address, settings

   # Enable debugging
   settings.DEBUG = 2  # DEBUG level 2
   print(get_mac_address(interface="Ethernet 3"))

   # Change the UDP port used for updating the ARP table (UDP packet)
   settings.PORT = 44444  # Default port for getmac is 55555
   print(get_mac_address(ip="192.168.0.1", network_request=True))


.. _usage-logging:

Logging and debugging
---------------------

Runtime messages and errors are recorded to the ``getmac`` logger using Python's :mod:`logging` module. Nothing is shown until logging is configured, e.g. with :func:`logging.basicConfig`. :attr:`~getmac.variables.Settings.DEBUG` controls how much detail is logged, and its documentation describes each level.

.. code-block:: python

   import logging

   from getmac import get_mac_address, settings

   logging.basicConfig(format="%(levelname)-8s %(message)s", level=logging.DEBUG)
   settings.DEBUG = 2

   get_mac_address(interface="lo")

When reporting an issue, use level 4. :ref:`module-api-logging` shows what the output looks like, and :doc:`troubleshooting` covers the common problems.


.. _usage-environment:

Environment variables
---------------------

A few environment variables change how getmac works. They're read once, when getmac is imported, so set them in the process environment (or before ``import getmac``).

``ARP_PATH``
   The file :class:`~getmac.getmac.ArpFile` reads the ARP table from, ``/proc/net/arp`` by default. It only applies on Linux (including WSL2 and Android). It's mostly useful in containers, e.g. to read the host's table (see :doc:`docker`).

``ANDROID_STORAGE``
   Used to detect Android. You don't set this, Android does.

``PATH``
   getmac copies ``PATH`` when it's imported and uses the copy to find commands. On POSIX systems, ``/sbin`` and ``/usr/sbin`` are added to the copy, since ``arp``, ``ip`` and friends often live there. On Windows, any ``Scripts`` directories are removed from it, so the real Windows ``getmac.exe`` is run instead of this package's script. It doesn't change your shell's ``PATH``, and changing ``os.environ`` after the import has no effect.

``LC_ALL``
   getmac sets ``LC_ALL=C`` for every command it runs, so the output isn't translated and can be parsed. That only has an effect on POSIX systems. On Windows, command output is still translated, see the ``ipconfig`` entry in :doc:`troubleshooting`.


.. _usage-errors:

Errors and exceptions
=====================

- **A lookup that finds nothing returns** :obj:`None`. This covers an interface that doesn't exist, a host that isn't in the ARP/NDP table, and a hostname that doesn't resolve. Exceptions raised by the platform-specific *methods* are caught and logged, and the next method is tried (see :ref:`module-api-fallback`). The one exception is a method forced with :attr:`~getmac.variables.Settings.FORCE_METHOD`, whose exceptions are not caught.
- :class:`ValueError` means a bad argument: an :mod:`ipaddress` network (getmac needs a host, not a network), or an unsupported type such as :class:`int`.
- :class:`RuntimeWarning` is shown (using :mod:`warnings`, and logged) when getmac has no methods for your platform and falls back to the generic ones (see :ref:`platforms-other`). It's only an exception if warnings are turned into errors, e.g. with ``python -W error`` or pytest's ``filterwarnings = error``.
- :class:`RuntimeError` means getmac has no working method for this kind of lookup on this platform: either no methods match the type of request and platform, or all of them failed their test (in other words, none of them work). Retrying won't help, it's an environment problem or a bug worth reporting. See :doc:`troubleshooting`. This is new in 1.0.0, 0.9.x returned :obj:`None` with a warning.


Limitations
===========

- The physical transport is assumed to be Ethernet or Wi-Fi. Others, such as Bluetooth or cellular, may work, but they're untested. I'm definitely open to pull requests or issues related to this, including error reports.
- Remote hosts have to be on your local network (see :ref:`usage-remote-hosts`).
- The accuracy and reliability of the MAC address retrieval may vary depending on the network configuration, the target host's settings, and other factors.

The rest, such as Android's restrictions, local IPs on Linux, and hostnames for IPv6 devices, are listed per platform in :ref:`platforms-known-issues`.
