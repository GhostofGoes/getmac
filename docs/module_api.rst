===============================
How methods are chosen and used
===============================

:func:`~getmac.get_mac_address` covers most uses of getmac. This page covers the internal methods used by getmac to resolve MAC addresses on various platforms.

Internally, getmac picks a *method* for each kind of lookup. The method is a class that knows a particular way of finding a :term:`MAC address`, such as reading ``/sys/class/net/<iface>/address`` or running ``ip neighbor show``. This page explains how those methods are chosen and used. To change them in your own code, see :doc:`custom_methods`. To contribute a method to getmac, see :doc:`adding_methods`.

.. warning::
   Most of what this page describes lives in :mod:`getmac.getmac` and is an internal :abbr:`API (application programming interface)` that may change between releases. Use it with care.

:doc:`architecture` describes where everything lives in the package. Every built-in method and its docstring is listed in the :doc:`api`.


Methods 101
===========

Methods
-------

A method is a subclass of :class:`~getmac.getmac.Method` and should set 3 attributes:

- :attr:`~getmac.getmac.Method.platforms`: a set with the platforms it works on, such as ``{"linux", "darwin"}``.
- :attr:`~getmac.getmac.Method.method_type`: the kind of lookup it does (see below).
- :attr:`~getmac.getmac.Method.network_request`: whether using it sends traffic on the network.

A method overrides two functions:

- :meth:`~getmac.getmac.Method.test`: a cheap check that the method can work on this system, such as "is the ``ip`` command installed?"
- :meth:`~getmac.getmac.Method.get`: performs the lookup. It takes one argument, and returns the result or :obj:`None`. The argument's meaning depends on the method, e.g. for an interface method, it would be the interface name (e.g. ``"eth0"``).

.. _module-api-method-types:

Method types
------------

.. list-table::
   :header-rows: 1
   :widths: 15 45 20 20

   * - ``method_type``
     - Used for
     - ``get()`` argument
     - ``get()`` returns
   * - ``ip4``
     - ``get_mac_address(ip=...)``, ``get_mac_address(hostname=...)``, and ``get_mac_address()`` with no arguments on Windows (see the note below)
     - IPv4 address
     - MAC address
   * - ``ip6``
     - ``get_mac_address(ip6=...)``
     - IPv6 address
     - MAC address
   * - ``ip``
     - Both ``ip4`` and ``ip6`` lookups
     - IPv4 or IPv6 address
     - MAC address
   * - ``iface``
     - ``get_mac_address(interface=...)``, and ``get_mac_address()`` with no arguments
     - Interface name
     - MAC address
   * - ``default_iface``
     - :func:`~getmac.get_default_interface`, and ``get_mac_address()`` with no arguments
     - Empty string
     - Interface name

.. note::
   ``get_mac_address()`` with no arguments does a ``default_iface`` lookup, then an ``iface`` lookup of the interface it finds. If the :term:`default interface` can't be found or it doesn't have a MAC, the first interface from :func:`socket.if_nameindex` that has a MAC and isn't a :term:`loopback interface` is used instead, except on Windows.

   On Windows with ``network_request=True`` (the default), it first gets the IP address of the interface with the default route from :func:`~getmac.utils.fetch_ip_using_dns`, and does an ``ip4`` lookup of that address. The ``default_iface`` lookup is only done if that doesn't find a MAC.

.. note::
   There is one cache per lookup type: ``ip4``, ``ip6``, ``iface`` and ``default_iface``.

.. _module-api-platforms:

Platforms
---------

The platform is a lowercase identifier, :attr:`consts.PLATFORM <getmac.variables.Constants.PLATFORM>`, unless you override it with :attr:`settings.OVERRIDE_PLATFORM <getmac.variables.Settings.OVERRIDE_PLATFORM>`. To see what your system is detected as:

.. code-block:: python

   from getmac.variables import consts

   print(consts.PLATFORM)  # For example, "linux"

The identifiers used by the built-in methods are listed in :attr:`Method.VALID_PLATFORM_NAMES <getmac.getmac.Method.VALID_PLATFORM_NAMES>`, and :doc:`platforms` lists the methods for each platform.

The platform ``"other"`` is used for methods that are generic enough to try on unknown systems, and are only used as a last resort if the current platform matches no method.

.. _module-api-choosing:

Choosing a method
-----------------

The first time a lookup is performed for a particular type (e.g. ``ip4``), the cache for that type is initialized by :func:`~getmac.getmac.initialize_method_cache`:

1. Selects methods in :data:`~getmac.getmac.METHODS` with a matching ``method_type``.
2. Selects methods whose ``platforms`` set includes the current platform, or ``"other"`` if nothing matches (see the section above).
3. If ``network_request=False``, it excludes methods that have ``network_request=True``.
4. Creates instances of the selected methods and calls their ``test()``. The first method that passes (returns :obj:`True`) becomes the *primary* method, stored in :data:`METHOD_CACHE[type] <getmac.getmac.METHOD_CACHE>`. The others that pass become *fallbacks*, stored in order in :data:`FALLBACK_CACHE[type] <getmac.getmac.FALLBACK_CACHE>`. Methods whose ``test()`` returns :obj:`False` or raises an exception are left out.

:func:`~getmac.getmac.initialize_method_cache` will raise :class:`RuntimeError` if:

- No method has the requested type.
- No method suits the platform, even after trying ``"other"``.
- Every candidate method fails its ``test()``.

.. note::
   The cache is built lazily on first lookup and reused for the rest of the process's life. Methods aren't tested again, so later changes to :data:`~getmac.getmac.METHODS`, to ``OVERRIDE_PLATFORM``, or to the system itself (such as installing a command) don't affect a type whose cache is already built.

.. _module-api-fallback:

Falling back during a lookup
----------------------------

Each lookup calls ``get()`` on the :term:`primary method` from the cache and:

- If ``get()`` returns a value, winner winner chicken dinner, that's the result.
- If ``get()`` returns :obj:`None`, the result is :obj:`None`. The fallbacks are **not** tried. :obj:`None` means "not found", for example "there's no such interface", *not* "this method doesn't work".
- If ``get()`` raises an exception, or sets ``self.unusable = True`` and returns :obj:`None`, the method is removed from the cache. The first fallback becomes the primary method, and the lookup is retried with it using the same argument. The exception is logged as a warning, not raised.
- A :class:`~subprocess.CalledProcessError` with exit code 1 is treated like returning :obj:`None`, because many commands exit with 1 when the interface or host doesn't exist. Any other exit code counts as a failure and leads to a fallback.
- A command that runs longer than :attr:`settings.COMMAND_TIMEOUT <getmac.variables.Settings.COMMAND_TIMEOUT>` is stopped, and the method is treated like one that raised an exception.
- With ``network_request=False``, methods that send :term:`network requests <network request>` (their ``network_request`` attribute is :obj:`True`) are skipped, both for the lookup and as fallbacks. They stay in the cache, since the cache may have been built by a lookup that allowed them.

.. _module-api-ipv4-network:

IPv4 lookups and network requests
---------------------------------

When :func:`~getmac.get_mac_address` looks up an IPv4 address (``ip=`` or ``hostname=``) with ``network_request=True`` (the default), it first tries to make sure the host is in the system's :term:`ARP table`:

1. If :class:`~getmac.getmac.ArpFile` is in the ``ip4`` cache, it's tried first, since reading ``/proc/net/arp`` is fast. If it fails, it's removed from the cache, but no other method is tried yet. If it finds the host, nothing is sent on the network.
2. Then, if the host wasn't found and :class:`~getmac.getmac.CtypesHost` or :class:`~getmac.getmac.ArpingHost` is in the ``ip4`` cache, it's made the primary method, since it sends an ARP request itself.
3. If neither applies, an empty :term:`UDP` packet is sent to the host on the port specified by :attr:`settings.PORT <getmac.variables.Settings.PORT>` to force the system to populate the ARP table.

Then the host is looked up with the ``ip4`` cache. If the UDP packet was sent and the host isn't found, it's looked up again until it's found or :attr:`settings.ARP_TIMEOUT <getmac.variables.Settings.ARP_TIMEOUT>` seconds have passed (by default, it isn't looked up again). IPv6 lookups send the UDP packet and use ``ARP_TIMEOUT`` the same way, but there's no ``ArpFile`` or ARP request step.


Seeing which methods are used
=============================

Inspecting the caches
---------------------

After a lookup, the caches show which methods were chosen. Converting a method instance to a string with :class:`str` gives its class name.

.. code-block:: python

   from getmac import get_mac_address
   from getmac.getmac import FALLBACK_CACHE, METHOD_CACHE

   # Force caches to be populated
   get_mac_address()

   # Print the name of each method in the cache
   for method_type, method in METHOD_CACHE.items():
       fallbacks = [str(m) for m in FALLBACK_CACHE[method_type]]
       print(f"{method_type}: {method!s}, fallbacks: {fallbacks}")

Example output on a Linux system:

.. code-block:: text

   ip4: None, fallbacks: []
   ip6: None, fallbacks: []
   iface: SysIfaceFile, fallbacks: ['FcntlIface', 'IpLinkIface']
   default_iface: DefaultIfaceLinuxRouteFile, fallbacks: ['DefaultIfaceIpRoute']

Two helper functions look methods up by name:

- :func:`~getmac.getmac.get_instance_from_cache` returns the cached *instance* of a method, primary or fallback, for one lookup type. The name must match the class name exactly, for example ``get_instance_from_cache("iface", "SysIfaceFile")``.
- :func:`~getmac.getmac.get_method_by_name` returns the *class* with a given name from :data:`~getmac.getmac.METHODS`, ignoring case. This is how ``FORCE_METHOD`` finds a method.

.. _module-api-logging:

Logging and debug output
------------------------

getmac logs to the ``getmac`` logger with Python's :mod:`logging` module, and :attr:`settings.DEBUG <getmac.variables.Settings.DEBUG>` controls how much detail is logged (the attribute's documentation describes the levels). Level 2 is the one to use to see how methods were chosen:

.. code-block:: python

   import logging

   from getmac import get_mac_address, settings

   logging.basicConfig(format="%(levelname)-8s %(message)s", level=logging.DEBUG)
   settings.DEBUG = 2

   get_mac_address(interface="lo")

Example output on Linux, shortened:

.. code-block:: text

   DEBUG    Initializing 'iface' method cache (platform: 'linux')
   DEBUG    13 type-filtered methods for 'iface': SysIfaceFile, FcntlIface, LanscanIface, ...
   DEBUG    6 platform-filtered methods for 'linux' (method_type='iface'): SysIfaceFile, ...
   DEBUG    Test failed for method 'IfconfigWithIfaceArg'
   DEBUG    Test failed for method 'IfconfigOther'
   DEBUG    Test failed for method 'NetstatIface'
   DEBUG    3 tested methods for 'iface': SysIfaceFile, FcntlIface, IpLinkIface
   ...
   DEBUG    Attempting get() (method='SysIfaceFile', method_type='iface', arg='lo')
   DEBUG    Raw MAC found: 00:00:00:00:00:00

The command-line equivalent is ``getmac -v -dd -i lo``, see :doc:`cli`.


Calling lookups directly
========================

get_by_method()
---------------

:func:`~getmac.getmac.get_by_method` does one lookup of a given type (e.g., ``"ip4"``) using the caches and fallbacks described above.

It returns whatever the method's ``get()`` returned, without the clean-up that :func:`~getmac.get_mac_address` does. Many built-in methods return the MAC the way the command printed it, so pass the result through :func:`~getmac.utils.clean_mac` to get a lowercase, colon-separated MAC (aka what is normally returned from :func:`~getmac.get_mac_address`).

.. code-block:: python

   from getmac import utils
   from getmac.getmac import get_by_method

   raw = get_by_method("iface", "lo")
   print(repr(raw))
   print(utils.clean_mac(raw))

Example output on Linux:

.. code-block:: text

   '00:00:00:00:00:00\n'
   00:00:00:00:00:00

A few more things to know:

- An empty argument returns :obj:`None` and logs an error, except for ``default_iface`` type methods, which take no argument.
- It raises :class:`RuntimeError` when no method can be used, as described in :ref:`module-api-choosing`.
- Its ``network_request`` argument is passed to :func:`~getmac.getmac.initialize_method_cache` when that type's cache is first built. It's also applied on every later lookup, where methods that send network requests are skipped, both as the primary method and as fallbacks (see :ref:`module-api-fallback`).

.. _module-api-get-default-interface:

get_default_interface()
-----------------------

:func:`~getmac.get_default_interface` is ``get_by_method("default_iface")``, so it can also raise :class:`RuntimeError`. It doesn't change the default interface that ``get_mac_address()`` remembers between calls (:attr:`gvars.DEFAULT_IFACE <getmac.variables.Variables.DEFAULT_IFACE>`).

.. code-block:: python

   from getmac import get_default_interface

   try:
       print(get_default_interface())
   except RuntimeError as err:
       print(err)


Settings
========

The settings are described in :ref:`configuration`. Two of them change which methods are used, and this section adds how they interact with method selection.

:attr:`~getmac.variables.Settings.FORCE_METHOD`
   The name of a method to use for every lookup, e.g. ``"IpLinkIface"``. The name is looked up in :data:`~getmac.getmac.METHODS`, ignoring case. If no method matches, the lookup logs an error and returns :obj:`None`. On the command line, use ``--force-method``. The :attr:`full rules <getmac.variables.Settings.FORCE_METHOD>` are in the attribute's documentation, and these are the parts that matter for method selection:

   - A new instance is created for each lookup, and ``test()`` is never called.
   - ``platforms``, ``method_type`` and ``network_request`` are ignored, and the caches aren't used or changed.
   - There's no fallback, and exceptions raised by the method are not caught.
   - It applies to every lookup type, including ``get_mac_address()`` called with no arguments.
   - For an IPv4 lookup with ``network_request=True``, ``get_mac_address()`` still goes through the steps in :ref:`module-api-ipv4-network` before calling the forced method, so the ``ip4`` cache is still built, and the UDP packet is still sent (unless the forced method is ``"CtypesHost"`` or ``"ArpingHost"`` *and* it's in the ``ip4`` cache, i.e. it passed its test, since they send an ARP request themselves; otherwise the UDP packet is still sent). If ``"ArpFile"`` is forced and the cached ``ArpFile`` instance finds the MAC in step 1, that's returned, and the forced method is never called.

:attr:`~getmac.variables.Settings.OVERRIDE_PLATFORM`
   Override the detected platform identifier to whatever you set, e.g. ``"linux"``. Use ``--override-platform`` on the command line. It's only read when a cache is built, so set it before the first lookup or :ref:`reset the caches <module-api-reset>` afterwards. It only changes which methods are chosen. Other platform-specific behavior in ``get_mac_address()``, such as how the default interface is found on Windows, still follows the detected platform.


Customizing methods
===================

To add your own method, remove a built-in one, or undo your changes in tests, see :doc:`custom_methods`.
