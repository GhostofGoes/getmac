========
Glossary
========

This page defines the technical terms that the getmac documentation uses.

.. glossary::

   ARP table
      A table that maps IPv4 addresses to MAC addresses. The operating system keeps this table. getmac reads it to find the MAC address of a remote host. ARP is the Address Resolution Protocol.

   NDP table
      The IPv6 equivalent of the ARP table. NDP is the Neighbor Discovery Protocol. Some platforms call this table the neighbor table or the neighbor cache.

   MAC address
      The hardware address of a network interface, for example ``00:11:22:33:44:55``. getmac returns MAC addresses in lowercase, with colons between the octets.

   Network interface
      A connection between the system and a network, for example ``eth0`` on Linux or ``Ethernet 3`` on Windows.

   Default interface
      The network interface that has the default route of the system.

   Loopback interface
      A virtual network interface for traffic from the system to itself. Its MAC address is ``00:00:00:00:00:00``.

   Remote host
      Another device on your local layer 2 network (your LAN or VLAN). getmac cannot get the MAC address of a device outside this network.

   Method
      A class that uses one technique to get a MAC address or an interface name. For example, a method can run a command or read a file. See :doc:`module_api`.

   Method type
      The type of lookup that a method does: ``ip4``, ``ip6``, ``ip``, ``iface`` or ``default_iface``. See :ref:`module-api-method-types`.

   Primary method
      The method that getmac uses first for a type of lookup. It is the first method that passes its test.

   Fallback
      A method that getmac uses when the primary method fails.

   Network request
      Traffic that getmac sends on the network to put a host in the ARP table or the NDP table. Examples are a UDP packet and an ARP request. You can disable network requests.

   Platform
      The lowercase name of the operating system, for example ``linux``, ``windows`` or ``darwin``. getmac selects methods for the platform.
