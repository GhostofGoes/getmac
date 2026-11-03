========
Glossary
========

The terms used throughout these docs.

.. glossary::

   MAC address
      The hardware address of a network interface, e.g. ``00:11:22:33:44:55``. getmac returns MACs in lowercase with colons between the octets, whatever format the platform printed them in.

   Network interface
      A connection between the system and a network, e.g. ``eth0`` on Linux or ``Ethernet 3`` on Windows.

   Default interface
      The network interface that has the system's default route, i.e. where traffic to the internet goes. This is what ``get_mac_address()`` with no arguments looks up.

   Loopback interface
      The virtual interface for traffic from the system to itself (``lo`` on Linux, ``lo0`` on macOS and the BSDs). getmac treats its MAC as ``00:00:00:00:00:00``.

   Remote host
      Another device on your local layer 2 network (your LAN or VLAN). getmac can't get the MAC of a device outside this network, since MACs don't cross routers.

   ARP table
      The operating system's table of IPv4 addresses and their MACs, filled in by the Address Resolution Protocol (ARP). getmac reads it to find the MAC of a remote host. Also called the ARP cache.

   NDP table
      The IPv6 equivalent of the ARP table, filled in by the Neighbor Discovery Protocol (NDP). Also called the neighbor table or neighbor cache.

   Link-local address
      An IPv6 address that only works on one network link, from ``fe80::/10`` (e.g. ``fe80::1``). The same link-local address can exist on more than one link, so it's usually written with a zone ID.

   Zone ID (scope ID)
      The part after the ``%`` in an address like ``fe80::1%en0`` or ``fe80::1%2``, which says which interface (by name or by index) a link-local address belongs to. See :ref:`usage-ipv6-zones`.

   Network request
      Traffic that getmac sends to get a host into the ARP or NDP table before looking it up: an ARP request, or a UDP packet to a high port. It can be disabled with ``network_request=False`` or ``--no-net``.

   Method
      A class that implements one technique for getting a MAC or interface name, such as running a command or reading a file. getmac has a method for each command it knows how to parse. See :doc:`module_api`.

   Method type
      The kind of lookup a method does: ``ip4``, ``ip6``, ``ip`` (both), ``iface``, or ``default_iface``. See :ref:`module-api-method-types`.

   Primary method
      The method getmac uses first for a type of lookup: the first one in :data:`~getmac.getmac.METHODS` for the platform that passes its test.

   Fallback
      A method that getmac switches to when the primary method fails (raises an exception or marks itself unusable).

   Platform
      The lowercase name of the operating system that getmac uses to pick methods, e.g. ``linux``, ``windows``, ``darwin``, ``freebsd``, or ``sunos``. See :ref:`module-api-platforms`.
