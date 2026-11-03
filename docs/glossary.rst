========
Glossary
========

The terms and abbreviations used throughout these docs. Pages link here the first time they use one.

.. glossary::

   MAC address
      The MAC (media access control) address is the hardware address of a network interface, e.g. ``00:11:22:33:44:55``. getmac returns MACs in lowercase with colons between the :term:`octets <octet>`, whatever format the platform printed them in.

   Octet
      One byte (8 bits). A MAC address is six octets, each written as two hex digits, like ``0a``.

   Network interface
      A connection between the system and a network, e.g. ``eth0`` on Linux or ``Ethernet 3`` on Windows.

   Default interface
      The network interface that has the system's default route, i.e. where traffic to the internet goes. This is what ``get_mac_address()`` with no arguments looks up.

   Loopback interface
      The virtual interface for traffic from the system to itself (``lo`` on Linux, ``lo0`` on macOS and the BSDs). getmac treats its MAC as ``00:00:00:00:00:00``.

   Remote host
      Another device on your local :term:`layer 2 network` (your :term:`LAN` or :term:`VLAN`). getmac can't get the MAC of a device outside this network, since MACs don't cross routers.

   LAN
      Local area network: the devices you can reach without going through a router, like everything on your home Wi-Fi.

   VLAN
      Virtual LAN: one physical network split into separate LANs. To getmac, each VLAN is its own LAN, so it only finds hosts on the same one.

   Layer 2 network
   Broadcast domain
      The part of a network where devices talk to each other directly by MAC address, with no router in between. A LAN or a VLAN is one. Remote hosts have to be on the same one as you.

   ARP table
      The operating system's table of IPv4 addresses and their MACs, filled in by the Address Resolution Protocol (ARP). getmac reads it to find the MAC of a remote host. Also called the ARP cache.

   NDP table
      The IPv6 equivalent of the ARP table, filled in by the Neighbor Discovery Protocol (NDP). Also called the neighbor table or neighbor cache.

   Link-local address
      An IPv6 address that only works on one network link, from ``fe80::/10`` (e.g. ``fe80::1``). The same link-local address can exist on more than one link, so it's usually written with a zone ID.

   Zone ID
   Scope ID
      The part after the ``%`` in an address like ``fe80::1%en0`` or ``fe80::1%2``, which says which interface (by name or by index) a link-local address belongs to. See :ref:`usage-ipv6-zones`.

   Network request
      Traffic that getmac sends to get a host into the ARP or NDP table before looking it up: an ARP request, or a UDP packet to a high port. It can be disabled with ``network_request=False`` or ``--no-net``.

   UDP
      User Datagram Protocol: a way to send a packet without setting up a connection first. getmac sends an empty UDP packet to a host so the system looks up its MAC. Nothing has to be listening on the port.

   DNS
      Domain Name System: what turns a hostname like ``home.router`` into an IP address. getmac uses it for the ``hostname`` argument.

   VPN
      Virtual private network: sends your traffic through an encrypted tunnel. The tunnel interface usually has no MAC, so when it's the default interface, getmac falls back to another interface.

   CAP_NET_RAW
      A Linux capability that lets a program send raw network packets without being root. ``arping`` needs it (or root) to send ARP requests.

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

   POSIX
      Portable Operating System Interface: the standard that Unix-like systems such as Linux, macOS, and the BSDs follow. In these docs, "POSIX systems" means everything except Windows.

   illumos
      An open-source operating system that grew out of OpenSolaris, used by OmniOS, OpenIndiana, and SmartOS. getmac treats it like Solaris (platform ``sunos``).

   WSL
      Windows Subsystem for Linux: runs Linux programs on Windows. getmac supports both WSL1 and WSL2 (see :doc:`platforms`).

   CPython
      The standard Python interpreter, the one you get from python.org.

   PyPy
      Another Python interpreter, often faster thanks to its just-in-time compiler. getmac is pure Python, so it runs on PyPy as is.

   PyPI
      The Python Package Index (pypi.org), where ``pip`` downloads packages from.

   Wheel
      The ready-to-install package format on PyPI (a ``.whl`` file). ``pip`` installs getmac from its wheel.

   sdist
      Source distribution: a ``.tar.gz`` of the source code, published to PyPI next to the wheel.
