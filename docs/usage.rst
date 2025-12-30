=====
Usage
=====

getmac provides a Python function, :func:`~getmac.getmac.get_mac_address`, and a command-line interface, :ref:`getmac <args>`.  The command-line interface is documented in :doc:`cli`. This page documents usage from Python as a library.

If a MAC address was found, :func:`~getmac.getmac.get_mac_address` will return a lowercase colon-separated MAC address as a string. If no MAC was found, or an exception occurred, :obj:`None` is returned.

Examples
========

Basic example:

.. code-block:: shell

   Python 3.11.4 (tags/v3.11.4:d2340ef, Jun  7 2023, 05:45:37) [MSC v.1934 64 bit (AMD64)] on win32
   Type "help", "copyright", "credits" or "license" for more information.
   Ctrl click to launch VS Code Native REPL
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


Updated ARP/NDP table before lookup
-----------------------------------

Update the ARP table (IPv4) or NDP list (IPv6) before looking up the MAC.
This results in a UDP packet being sent to the target IP address on port 55555 (by default).


.. code-block:: python

   from getmac import get_mac_address

   get_mac_address(ip="10.0.0.1", network_request=True)


Changing settings
-----------------

Available settings are documented in :ref:`configuration`. Here's an example of changing some settings at runtime:

.. code-block:: python

   from getmac import get_mac_address, settings

   # Enable debugging
   settings.DEBUG = 2  # DEBUG level 2
   print(get_mac_address(interface="Ethernet 3"))

   # Change the UDP port used for updating the ARP table (UDP packet)
   settings.PORT = 55555  # Default port for getmac is 55555
   print(get_mac_address(ip="192.168.0.1", network_request=True))


Using ipaddress objects
-----------------------

You can also use the standard library's :mod:`ipaddress` module to specify IP addresses. This works for both IPv4 and IPv6 addresses. The ``ip`` argument also accepts ``IPv6Address`` and ``IPv6Interface`` objects, and will treat them as IPv6 addresses. The ``ip6`` argument is not needed when using these objects, but can be used if desired.

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

Get the name of the system's default network interface using :func:`~getmac.getmac.get_default_interface`. This leverages the same logic that getmac uses internally to determine the default interface (e.g. for when :func:`~getmac.getmac.get_mac_address` is called without any arguments).

.. warning::
   This currently doesn't work on Windows platforms.
   It should work on other platforms, including Linux, OSX, and most BSDs.

.. code-block:: python

   from getmac import get_default_interface
   print(get_default_interface())


.. _configuration:

Configuration
=============

Settings that affect the behavior of getmac are in the :mod:`~getmac.variables` module, with the exception of the logging settings, which are handled by Python's :mod:`logging` module. The following settings are available:

- ``logging.getLogger("getmac")``: Runtime messages and errors are recorded to the ``getmac`` logger using Python's :mod:`logging` module. They can be configured by using :func:`logging.basicConfig` or adding :class:`logging.Handler` instances to the ``getmac`` logger.
- :attr:`~getmac.variables.Settings.DEBUG`: integer value that controls debugging output. The higher the value, the more output you get.
- :attr:`~getmac.variables.Settings.PORT`: the UDP port used to populate the ARP table (IPv4) or NDP list (IPv6) when looking up MACs for hosts or IPs (see the documentation of the ``network_request`` argument in :func:`~getmac.getmac.get_mac_address` for details).
- :attr:`~getmac.variables.Settings.OVERRIDE_PLATFORM`: Override the platform detection with the given value (e.g. ``"linux"``, ``"windows"``, ``"freebsd"``, etc). Any values returned by :func:`platform.system` are valid.
- :attr:`~getmac.variables.Settings.FORCE_METHOD`: Name of method to use. This will force a specific method to be used, e.g. :class:`getmac.getmac.IpNeighborShow` with the string ``"IpNeighborShow"``. This will be used regardless of the method's type or platform compatibility, and :func:`~getmac.getmac.Method.test` will NOT be checked! The list of available methods is in :data:`getmac.getmac.METHODS`.


Notes
=====

- ``"localhost"`` or ``"127.0.0.1"`` will always return ``"00:00:00:00:00:00"``, as this is the MAC address of the loopback interface.
- If none of the arguments are selected, the default network interface for the system will be used. If the default network interface cannot be determined, then it will attempt to fallback to typical defaults for the platform (``Ethernet`` on Windows, ``em0`` on BSD, ``en0`` on OSX/Darwin, and ``eth0`` otherwise). If that fails, then it will fallback to ``lo`` on POSIX systems.
- The first four arguments to :func:`~getmac.getmac.get_mac_address` are mutually exclusive. ``network_request`` does not have any functionality when the ``interface`` argument is specified, and can be safely set if using in a script.
- **Most Exceptions will be handled silently and returned as a None.** If you run into problems, you can set :attr:`~getmac.variables.Settings.DEBUG` to true and get more information about what's happening. If you're still having issues, please create an `issue on GitHub <https://github.com/GhostofGoes/getmac/issues>`_ and include the output with :attr:`~getmac.variables.Settings.DEBUG` enabled. As of version 1.0.0, a :class:`RuntimeError` is raised in cases where no possible methods are found matching the type of request and platform or all methods found fail to test (in other words, don't work).


Limitations & Known Issues
==========================

- The physical transport is assumed to be Ethernet (802.3). Others, such as Wi-Fi (802.11), are currently not tested or considered. I plan to address this in the future, and am definitely open to pull requests or issues related to this, including error reports.
- "Remote hosts" refer to hosts in *your local layer 2 network*, also known as a "broadcast domain", "LAN", or "VLAN". As far as I know, there is not a reliable method to get a MAC address for a remote host external to the LAN. If you know any methods otherwise, please `a issue on GitHub <https://github.com/GhostofGoes/getmac/issues>`_ or shoot me an email, I'd love to be wrong about this.
- Some methods may not work on certain platforms or configurations. If a method fails, getmac will try the next available method until it finds one that works or exhausts all options.
- The accuracy and reliability of the MAC address retrieval may vary depending on the network configuration, the target host's settings, and other factors. Please refer to the documentation of each method for more details on their behavior and limitations.
- Depending on the platform, there could be a performance detriment, due to heavy usage of regular expressions.
- Platform test coverage is imperfect. If you're having issues, then you might be using a platform I haven't been able to test. Keep calm, open a GitHub issue, and I'd be more than happy to help.
- Linux, WSL: Getting the mac of a local interface IP does not currently work (``getmac --ip 10.0.0.4`` will fail if ``10.0.0.4`` is the IP address of a local interface). This issue may be present on other POSIX systems as well.
- Hostnames for IPv6 devices are not yet supported.
- Windows: the "default" (used when no arguments set or specified) of selecting the default route interface only works effectively if ``network_request`` is enabled. If not, ``Ethernet`` is used as the default.
- IPv6 support is good but lags behind IPv4 in some places and isn't as well-tested across the supported platform set.
