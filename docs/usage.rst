=====
Usage
=====

getmac provides a Python function, :func:`~getmac.getmac.get_mac_address`, and a command-line interface, :ref:`getmac <args>`. This page covers using getmac from Python as a library. The command-line interface is documented in :doc:`cli`.

If a MAC address was found, :func:`~getmac.getmac.get_mac_address` returns it as a lowercase, colon-separated string, e.g. ``'00:11:22:33:44:55'``. If no MAC was found, :obj:`None` is returned. See :ref:`usage-errors` for the exceptions it can raise.

Examples
========

Basic example:

.. code-block:: pycon

   >>> from getmac import get_mac_address
   >>> get_mac_address(ip='192.168.0.1')
   '00:11:22:33:44:55'


Interface names
---------------

.. code-block:: python

   from getmac import get_mac_address

   # Linux example
   get_mac_address(interface="eth0")

   # Windows example
   get_mac_address(interface="Ethernet 3")

On Windows, the name must match the whole connection name (``Ethernet 3``) or adapter description (``Intel(R) Ethernet Connection I217-V``). Case doesn't matter.


IP addresses and hostnames
--------------------------

.. code-block:: python

   from getmac import get_mac_address

   # IPv4 example
   get_mac_address(ip="192.168.0.1")

   # IPv6 example
   get_mac_address(ip6="::1")

   # Hostname example
   get_mac_address(hostname="localhost")

Only one of ``interface``, ``ip``, ``ip6``, and ``hostname`` can be used at a time. A hostname is resolved to an IPv4 address with DNS, then looked up like ``ip``. ``"localhost"`` and ``"127.0.0.1"`` always return ``"00:00:00:00:00:00"``, the MAC of the loopback interface.


Default interface
-----------------

With no arguments, you get the MAC of the system's default network interface, i.e. the one with the default route:

.. code-block:: python

   from getmac import get_mac_address

   get_mac_address()

If the default interface can't be determined (for example, if there aren't any routes) or doesn't have a MAC (for example, a VPN tunnel), then the first interface that has a MAC and isn't a loopback interface is used. If there isn't one, :obj:`None` is returned. On Windows, only the default interface is used.

To get the *name* of the default interface, use :func:`~getmac.getmac.get_default_interface`. It uses the same logic that :func:`~getmac.getmac.get_mac_address` uses when it's called without any arguments.

.. code-block:: python

   from getmac import get_default_interface

   print(get_default_interface())  # e.g. "eth0", or "Ethernet 2" on Windows


Remote hosts and network requests
---------------------------------

Finding the MAC of a remote host means finding it in the system's ARP table (IPv4) or NDP table (IPv6). The host is only in the table if the system has talked to it recently, so by default (``network_request=True``) getmac tries to get it in there first:

- On Linux and macOS with ``arping`` installed, and on Windows, getmac sends an ARP request to the host and waits for the reply.
- Otherwise, getmac sends an empty UDP packet to the host on port ``55555`` (:attr:`~getmac.variables.Settings.PORT`). To send the packet, the system has to resolve the host's MAC with ARP (or NDP), which adds it to the table.

Set ``network_request=False`` to only use what's already in the table, for example if you have requirements to prevent network traffic:

.. code-block:: python

   from getmac import get_mac_address

   get_mac_address(ip="10.0.0.1", network_request=False)

The host's entry is only added to the table once it replies, which can take longer than getmac takes to check the table. To keep checking for it for up to a number of seconds, set :attr:`~getmac.variables.Settings.ARP_TIMEOUT` (``--arp-timeout`` on the command line). Lookups of hosts that don't reply take this much longer. This doesn't apply when getmac sends an ARP request itself, since it waits for the reply.

.. code-block:: python

   from getmac import get_mac_address, settings

   settings.ARP_TIMEOUT = 1.0  # Default is 0, check once
   get_mac_address(ip="10.0.0.1")

``network_request`` does not have any functionality when the ``interface`` argument is specified, so it can be safely set if using in a script. :ref:`module-api-ipv4-network` has the exact sequence of what getmac does.


Changing settings
-----------------

Available settings are documented in :ref:`configuration`. Here's an example of changing some settings at runtime:

.. code-block:: python

   from getmac import get_mac_address, settings

   # Enable debugging
   settings.DEBUG = 2  # DEBUG level 2
   print(get_mac_address(interface="Ethernet 3"))

   # Change the UDP port used for updating the ARP table (UDP packet)
   settings.PORT = 44444  # Default port for getmac is 55555
   print(get_mac_address(ip="192.168.0.1", network_request=True))


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

   ipv6_addr = ip_address("::1")
   print(get_mac_address(ip=ipv6_addr))

   ipv4_iface = IPv4Interface("192.168.0.1/24")
   print(get_mac_address(ip=ipv4_iface))

   ipv6_iface = IPv6Interface("::1/128")
   print(get_mac_address(ip=ipv6_iface))

All four lookup arguments also accept :class:`bytes`, which are decoded as UTF-8.


Logging and debugging
---------------------

Runtime messages and errors are recorded to the ``getmac`` logger using Python's :mod:`logging` module. Nothing is shown until logging is configured, e.g. with :func:`logging.basicConfig`. :attr:`~getmac.variables.Settings.DEBUG` controls how much detail is logged:

- ``0`` (the default): warnings and errors, plus a few debug messages, such as when a cache is built and the raw MAC that was found.
- ``1``: the methods that failed their test, the contents of the caches, each lookup attempt, and how long the lookup took.
- ``2``: the methods left after filtering by type, by platform, and by their test.
- ``3``: every command that's run.
- ``4``: the output of every command, and the full list of methods.

.. code-block:: python

   import logging

   from getmac import get_mac_address, settings

   logging.basicConfig(format="%(levelname)-8s %(message)s", level=logging.DEBUG)
   settings.DEBUG = 2

   get_mac_address(interface="lo")

When reporting an issue, use level 4. :ref:`module-api-logging` shows what the output looks like, and :doc:`troubleshooting` covers the common problems.


.. _configuration:

Configuration
=============

Settings that affect the behavior of getmac are attributes of ``getmac.settings`` (an instance of :class:`~getmac.variables.Settings`). Set them before calling :func:`~getmac.getmac.get_mac_address`. The exception is logging, which is handled by Python's :mod:`logging` module (see above). The following settings are available:

- :attr:`~getmac.variables.Settings.DEBUG`: integer value that controls debugging output. The higher the value, the more output you get (``0`` is off, ``4`` is roughly the highest).
- :attr:`~getmac.variables.Settings.PORT`: the UDP port used to populate the ARP table (IPv4) or NDP table (IPv6) when looking up MACs for hosts or IPs. Default is ``55555``.
- :attr:`~getmac.variables.Settings.ARP_TIMEOUT`: how long to keep checking the ARP table (IPv4) or NDP table (IPv6) for a host after sending the UDP packet, in seconds. ``0`` (the default) checks once, without waiting.
- :attr:`~getmac.variables.Settings.COMMAND_TIMEOUT`: how long to wait for a command that getmac runs (such as ``arp`` or ``ipconfig.exe``) to finish, in seconds. A command that takes longer is stopped, and the next method is tried. The default is 15 seconds, and :obj:`None` or ``0`` waits for as long as the command takes.
- :attr:`~getmac.variables.Settings.OVERRIDE_PLATFORM`: Override the platform detection with the given value (e.g. ``"linux"``, ``"windows"``, ``"freebsd"``, etc). Any value returned by :func:`platform.system` is valid. Set it before the first lookup.
- :attr:`~getmac.variables.Settings.FORCE_METHOD`: Name of a method to use for every lookup, e.g. ``"IpNeighborShow"`` for :class:`~getmac.getmac.IpNeighborShow`. It's used regardless of its method type or platform compatibility, and :func:`~getmac.getmac.Method.test` is NOT checked! The list of available methods is in :data:`getmac.getmac.METHODS` and the :doc:`api`.

The last two are for debugging and testing. :doc:`module_api` explains how they interact with method selection.


.. _usage-errors:

Errors and exceptions
=====================

- **A lookup that finds nothing returns** :obj:`None`. This covers an interface that doesn't exist, a host that isn't in the ARP/NDP table, and a hostname that doesn't resolve. Exceptions raised by the platform-specific *methods* are caught and logged, and the next method is tried (see :ref:`module-api-fallback`). The one exception is a method forced with :attr:`~getmac.variables.Settings.FORCE_METHOD`, whose exceptions are not caught.
- :class:`ValueError` means a bad argument: an :mod:`ipaddress` network (getmac needs a host, not a network), or an unsupported type such as :class:`int`.
- :class:`RuntimeError` means getmac has no working method for this kind of lookup on this platform: either no methods match the type of request and platform, or all of them failed their test (in other words, none of them work). Retrying won't help, it's an environment problem or a bug worth reporting. See :doc:`troubleshooting`. This is new in 1.0.0, 0.9.x returned :obj:`None` with a warning.


Limitations
===========

- The physical transport is assumed to be Ethernet (802.3). Others, such as Wi-Fi (802.11), are currently not tested or considered. I plan to address this in the future, and am definitely open to pull requests or issues related to this, including error reports.
- "Remote hosts" refer to hosts in *your local layer 2 network*, also known as a "broadcast domain", "LAN", or "VLAN". As far as I know, there is not a reliable method to get a MAC address for a remote host external to the LAN. If you know any methods otherwise, please `open an issue on GitHub <https://github.com/GhostofGoes/getmac/issues>`_ or shoot me an email, I'd love to be wrong about this.
- Hostnames for IPv6 devices are not yet supported.
- The accuracy and reliability of the MAC address retrieval may vary depending on the network configuration, the target host's settings, and other factors.
- Depending on the platform, there could be a performance detriment, due to heavy usage of regular expressions.
- Platform test coverage is imperfect. If you're having issues, then you might be using a platform I haven't been able to test. Keep calm, open a GitHub issue, and I'd be more than happy to help.

Platform-specific limitations, such as Android's restrictions and local IPs on Linux, are listed in :ref:`platforms-known-issues`.
