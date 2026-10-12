=====
Usage
=====

getmac has a Python function, :func:`~getmac.getmac.get_mac_address`, and a command-line interface, :ref:`getmac <args>`. This page shows how to use getmac from Python as a library. :doc:`cli` shows how to use the command-line interface.

:func:`~getmac.getmac.get_mac_address` returns the MAC address as a lowercase string with colons between the octets, for example ``'00:11:22:33:44:55'``. If getmac does not find a MAC address, the function returns :obj:`None`. For the errors that the function can raise, see :ref:`usage-errors`.

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


Update the ARP or NDP table before the lookup
---------------------------------------------

To find the MAC address of a remote host, the host must be in a table on this system. For IPv4, this is the ARP table. For IPv6, this is the NDP table. With ``network_request=True`` (the default), getmac tries to put the host in the table before the lookup. Usually, getmac sends a UDP packet to the target IP address for this. The packet goes to port 55555 by default. :ref:`module-api-ipv4-network` gives the full sequence.

.. code-block:: python

   from getmac import get_mac_address

   get_mac_address(ip="10.0.0.1", network_request=True)

The system adds the host to the table only when the host replies. The reply can arrive after getmac checks the table. To make getmac check the table again for a maximum number of seconds, set :attr:`~getmac.variables.Settings.ARP_TIMEOUT`. On the command line, use ``--arp-timeout``.

.. code-block:: python

   from getmac import get_mac_address, settings

   settings.ARP_TIMEOUT = 1.0  # The default is 0, which checks the table one time
   get_mac_address(ip="10.0.0.1")


Change the settings
-------------------

:ref:`configuration` lists the settings. This example changes some settings at runtime:

.. code-block:: python

   from getmac import get_mac_address, settings

   # Enable debugging
   settings.DEBUG = 2  # DEBUG level 2
   print(get_mac_address(interface="Ethernet 3"))

   # Change the UDP port that getmac sends the packet to (the default port is 55555)
   settings.PORT = 44444
   print(get_mac_address(ip="192.168.0.1", network_request=True))


Use ipaddress objects
---------------------

The ``ip`` and ``ip6`` arguments also accept objects from the :mod:`ipaddress` module in the standard library:

- ``ip`` accepts :class:`~ipaddress.IPv4Address` and :class:`~ipaddress.IPv4Interface` objects.
- ``ip`` also accepts :class:`~ipaddress.IPv6Address` and :class:`~ipaddress.IPv6Interface` objects. getmac uses them as IPv6 addresses, the same as the ``ip6`` argument.
- ``ip6`` accepts :class:`~ipaddress.IPv6Address` and :class:`~ipaddress.IPv6Interface` objects.
- Network objects, such as :class:`~ipaddress.IPv4Network`, cause a :class:`ValueError`. getmac needs the address of one host, not of a network.

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

Default interface name
----------------------

:func:`~getmac.getmac.get_default_interface` returns the name of the default network interface of the system. It uses the same logic as :func:`~getmac.getmac.get_mac_address` when you call that function without arguments.

.. code-block:: python

   from getmac import get_default_interface
   print(get_default_interface())


.. _configuration:

Configuration
=============

The settings that change how getmac operates are in the :mod:`~getmac.variables` module. The logging settings are the exception. Python's :mod:`logging` module controls them. These settings are available:

- ``logging.getLogger("getmac")``: getmac records messages and errors to the ``getmac`` logger of the :mod:`logging` module. To configure the logger, use :func:`logging.basicConfig`, or add :class:`logging.Handler` instances to the ``getmac`` logger.
- :attr:`~getmac.variables.Settings.DEBUG`: an integer that controls the debug output. A higher value gives more output.
- :attr:`~getmac.variables.Settings.PORT`: the UDP port that getmac sends a packet to, to populate the ARP table (IPv4) or the NDP table (IPv6). For more information, see the ``network_request`` argument of :func:`~getmac.getmac.get_mac_address`.
- :attr:`~getmac.variables.Settings.ARP_TIMEOUT`: the maximum time, in seconds, that getmac checks the ARP or NDP table for a host after it sends the UDP packet. The default is ``0``, which checks the table one time and does not wait.
- :attr:`~getmac.variables.Settings.OVERRIDE_PLATFORM`: replaces the detected platform with this value, for example ``"linux"``, ``"windows"`` or ``"freebsd"``. All values that :func:`platform.system` returns are valid.
- :attr:`~getmac.variables.Settings.FORCE_METHOD`: the name of a method that getmac must use, for example ``"IpNeighborShow"`` for :class:`getmac.getmac.IpNeighborShow`. getmac uses this method for every lookup, and ignores its type and platforms. getmac does **not** call :func:`~getmac.getmac.Method.test` for it. :data:`getmac.getmac.METHODS` lists the available methods.


Notes
=====

- ``"localhost"`` and ``"127.0.0.1"`` always return ``"00:00:00:00:00:00"``. This is the MAC address of the loopback interface.
- You can use only one of the first four arguments of :func:`~getmac.getmac.get_mac_address`: ``interface``, ``ip``, ``ip6`` or ``hostname``.
- ``network_request`` has no effect with the ``interface`` argument. Thus, a script can set it for all lookups.

Calls without arguments
-----------------------

If you give none of the first four arguments, getmac uses the default network interface of the system. If getmac cannot find the default interface, or the default interface has no MAC address, getmac uses a different interface:

- getmac uses the first interface that has a MAC address and is not a loopback interface. For example, the default interface can be missing when the system has no routes. A VPN tunnel is an example of an interface with no MAC address.
- If no interface agrees with these conditions, the function returns :obj:`None`.
- On Windows, getmac uses only the default interface.

.. _usage-errors:

Errors
------

- getmac catches most exceptions and returns :obj:`None`. This includes the exceptions that a method raises.
- If you set :attr:`~getmac.variables.Settings.FORCE_METHOD`, getmac does not catch the exceptions of that method.
- :func:`~getmac.getmac.get_mac_address` raises a :class:`RuntimeError` when no method can do the lookup. This occurs when no method agrees with the type of lookup and the platform, or when all those methods fail their test. This behavior started in version 1.0.0.
- :func:`~getmac.getmac.get_mac_address` raises a :class:`ValueError` for an :mod:`ipaddress` network object, or for an argument of an unknown type.

If you have problems, set :attr:`~getmac.variables.Settings.DEBUG` to a value of ``1`` or more to get more information. See :doc:`troubleshooting` for more steps.


Limitations and known issues
============================

- getmac assumes that the physical transport is Ethernet (802.3). I do not test or consider other transports at this time, such as Wi-Fi (802.11). I plan to address this in the future. Pull requests and issues about this are welcome, and error reports also.
- A "remote host" is a host in *your local layer 2 network*. Other names for this network are "broadcast domain", "LAN", and "VLAN". As far as I know, no reliable method gets the MAC address of a remote host outside the LAN. If you know a method, please `open an issue on GitHub <https://github.com/GhostofGoes/getmac/issues>`_ or send me an email. I would like to be wrong about this.
- Some methods may not work on some platforms or configurations. If a method fails, getmac tries the next available method. getmac stops when a method works, or when no more methods are available.
- The accuracy and reliability of the result can change with the network configuration, the settings of the target host, and other factors. The documentation of each method in the :doc:`api` gives more information about its behavior and limitations.
- On some platforms, getmac can be slow, because it uses many regular expressions.
- The tests do not cover all platforms. If you have problems, your platform may be one that I did not test. Please open a GitHub issue, and I will help.
- Linux, WSL: getmac cannot get the MAC address of the IP address of a local interface. For example, ``getmac --ip 10.0.0.4`` fails if ``10.0.0.4`` is the IP address of a local interface. Other POSIX systems may have this issue also.
- getmac does not support hostnames for IPv6 devices yet.
- Android: newer versions of Android do not have many of the commands that getmac uses. They also restrict access to network information. Thus, getmac may find nothing. `BusyBox <https://busybox.net/>`__, or the ``iproute2`` and ``net-tools`` packages from `Termux <https://termux.dev/>`__, add the missing commands. Android's restrictions can still block these commands.
- Windows: ``ipconfig.exe`` is a fallback for when ``getmac.exe`` does not work. It finds interfaces by name only when its output is in English, because Windows translates the adapter headers.
- IPv6 support is good, but it is less complete than IPv4 support in some areas. I also test IPv6 less on the supported platforms.
