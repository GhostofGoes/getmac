=====
Usage
=====

getmac provides a Python function, :func:`~getmac.getmac.get_mac_address`, and a command-line interface, :ref:`getmac <args>`.  The command-line interface is documented in :doc:`cli`. This page documents usage from Python as a library.

Examples
========

.. code-block:: python

   from getmac import get_mac_address

   eth_mac = get_mac_address(interface="eth0")
   win_mac = get_mac_address(interface="Ethernet 3")
   ip_mac = get_mac_address(ip="192.168.0.1")
   ip6_mac = get_mac_address(ip6="::1")
   host_mac = get_mac_address(hostname="localhost")
   updated_mac = get_mac_address(ip="10.0.0.1", network_request=True)

   # Enable debugging
   from getmac import getmac
   getmac.DEBUG = 2  # DEBUG level 2
   print(getmac.get_mac_address(interface="Ethernet 3"))

   # Change the UDP port used for updating the ARP table (UDP packet)
   from getmac import getmac
   getmac.PORT = 55555  # Default port is 55555
   print(getmac.get_mac_address(ip="192.168.0.1", network_request=True))


Configuration
=============

TODO: update these for new settings classes
!!


- ``logging.getLogger("getmac")``: Runtime messages and errors are recorded to the ``getmac`` logger using Python's :mod:`logging` module. They can be configured by using :func:`logging.basicConfig` or adding :class:`logging.Handler` instances to the logger named ``"getmac"``.
- :attr:`~getmac.variables.Settings.DEBUG`: integer value that controls debugging output. The higher the value, the more output you get.
- :attr:`~getmac.variables.Settings.PORT`: the UDP port used to populate the ARP table (IPv4) or NDP list (IPv6) when looking up MACs for hosts or IPs (see the documentation of the ``network_request`` argument in :func:`~getmac.getmac.get_mac_address` for details).
- :attr:`getmac.variables.Settings.OVERRIDE_PLATFORM`: Override the platform detection with the given value (e.g. ``"linux"``, ``"windows"``, ``"freebsd"``, etc). Any values returned by :func:`platform.system` are valid.
- :attr:`~getmac.variables.Settings.FORCE_METHOD`: Name of method to use. This will force a specific method to be used, e.g. :class:`getmac.getmac.IpNeighborShow` with the string ``"IpNeighborShow"``. This will be used regardless of the method's type or platform compatibility, and :func:`Method.test() <getmac.getmac.Method.test>` will NOT be checked! The list of available methods is in :data:`getmac.getmac.METHODS`.
