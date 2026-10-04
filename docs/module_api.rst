====================
Using the module API
====================

:func:`~getmac.getmac.get_mac_address` covers most uses of getmac. This page covers the internal methods used by getmac to resolve MAC addresses on various platforms.

Internally, getmac picks a *method* for each kind of lookup. The method is a class that knows a particular way of finding a MAC address, such as reading ``/sys/class/net/<iface>/address`` or running ``ip neighbor show``. This page explains how those methods work, and how to implement a new method.

.. warning::
   Most of what this page describes lives in :mod:`getmac.getmac` and is an internal API that may change between releases. Use it with care.


Where things live
=================

- ``getmac``: :func:`~getmac.getmac.get_mac_address` and :func:`~getmac.getmac.get_default_interface` (the names in ``__all__``), plus ``settings`` and ``__version__``, which can also be imported from it. Nothing else is imported into the top-level package.
- :mod:`getmac.getmac`: the :class:`~getmac.getmac.Method` base class, the built-in methods, the :data:`~getmac.getmac.METHODS` list, the :data:`~getmac.getmac.METHOD_CACHE` and :data:`~getmac.getmac.FALLBACK_CACHE` dicts, and lower-level functions such as :func:`~getmac.getmac.get_by_method` and :func:`~getmac.getmac.initialize_method_cache`.
- :mod:`getmac.variables`: the ``settings``, ``consts`` and ``gvars`` objects, documented as the :class:`~getmac.variables.Settings`, :class:`~getmac.variables.Constants` and :class:`~getmac.variables.Variables` classes.
- :mod:`getmac.utils`: helper functions used by methods, such as :func:`~getmac.utils.popen` and :func:`~getmac.utils.search`.

``Method`` isn't exported from the top-level package, so import it with ``from getmac.getmac import Method``. Every built-in method and its docstring is listed in the :doc:`api` reference.


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
     - :func:`~getmac.getmac.get_default_interface`, and ``get_mac_address()`` with no arguments
     - Empty string
     - Interface name

.. note::
   ``get_mac_address()`` with no arguments does a ``default_iface`` lookup, then an ``iface`` lookup of the interface it finds. If the default interface can't be found or it doesn't have a MAC, the first interface from :func:`socket.if_nameindex` that has a MAC and isn't a loopback interface is used instead, except on Windows.

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

The identifiers used by the built-in methods are listed in :attr:`Method.VALID_PLATFORM_NAMES <getmac.getmac.Method.VALID_PLATFORM_NAMES>`.

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

Each lookup calls ``get()`` on the primary method from the cache and:

- If ``get()`` returns a value, winner winner chicken dinner, that's the result.
- If ``get()`` returns :obj:`None`, the result is :obj:`None`. The fallbacks are **not** tried. :obj:`None` means "not found", for example "there's no such interface", *not* "this method doesn't work".
- If ``get()`` raises an exception, or sets ``self.unusable = True`` and returns :obj:`None`, the method is removed from the cache. The first fallback becomes the primary method, and the lookup is retried with it using the same argument. The exception is logged as a warning, not raised.
- A :class:`~subprocess.CalledProcessError` with exit code 1 is treated like returning :obj:`None`, because many commands exit with 1 when the interface or host doesn't exist. Any other exit code counts as a failure and leads to a fallback.
- With ``network_request=False``, methods that send network requests (their ``network_request`` attribute is :obj:`True`) are skipped, both for the lookup and as fallbacks. They stay in the cache, since the cache may have been built by a lookup that allowed them.

.. _module-api-ipv4-network:

IPv4 lookups and network requests
---------------------------------

When :func:`~getmac.getmac.get_mac_address` looks up an IPv4 address (``ip=`` or ``hostname=``) with ``network_request=True`` (the default), it first tries to make sure the host is in the system's ARP table:

1. If :class:`~getmac.getmac.ArpFile` is in the ``ip4`` cache, it's tried first, since reading ``/proc/net/arp`` is fast. If it fails, it's removed from the cache, but no other method is tried yet.
2. Otherwise, if :class:`~getmac.getmac.CtypesHost` or :class:`~getmac.getmac.ArpingHost` is in the ``ip4`` cache, it's made the primary method, since it sends an ARP request itself.
3. If neither applies, an empty UDP packet is sent to the host on the port specified by :attr:`settings.PORT <getmac.variables.Settings.PORT>` to force the system to populate the ARP table.

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

getmac logs to the ``getmac`` logger with Python's :mod:`logging` module. It attaches a :class:`~logging.NullHandler` to that logger, so nothing is shown until logging is configured. :attr:`settings.DEBUG <getmac.variables.Settings.DEBUG>` controls how much detail is logged:

- ``0`` (the default): warnings, errors, and a few debug messages, such as when a cache is built and the raw MAC that was found.
- ``1``: failed tests, the contents of the caches, each ``get()`` attempt, and how long the lookup took.
- ``2``: the methods left after filtering by type, by platform, and by ``test()``.
- ``3``: every command that's run.
- ``4``: the output of every command, and the full :data:`~getmac.getmac.METHODS` list.

.. code-block:: python

   import logging

   from getmac import get_mac_address, settings

   logging.basicConfig(format="%(levelname)-8s %(message)s", level=logging.DEBUG)
   settings.DEBUG = 2

   get_mac_address(interface="lo")

Example output on Linux, shortened:

.. code-block:: text

   DEBUG    Initializing 'iface' method cache (platform: 'linux')
   DEBUG    12 type-filtered methods for 'iface': SysIfaceFile, FcntlIface, LanscanIface, ...
   DEBUG    6 platform-filtered methods for 'linux' (method_type='iface'): SysIfaceFile, FcntlIface, IfconfigWithIfaceArg, IfconfigOther, IpLinkIface, NetstatIface
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

It returns whatever the method's ``get()`` returned, without the clean-up that :func:`~getmac.getmac.get_mac_address` does. Many built-in methods return the MAC the way the command printed it, so pass the result through :func:`~getmac.utils.clean_mac` to get a lowercase, colon-separated MAC (aka what is normally returned from :func:`~getmac.getmac.get_mac_address`).

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
- Its ``network_request`` argument has the same effect as in :func:`~getmac.getmac.initialize_method_cache`, and **only applies if that type's cache hasn't been built yet**.

get_default_interface()
-----------------------

:func:`~getmac.getmac.get_default_interface` is ``get_by_method("default_iface")``, so it can also raise :class:`RuntimeError`. It doesn't change the default interface that ``get_mac_address()`` remembers between calls (:attr:`gvars.DEFAULT_IFACE <getmac.variables.Variables.DEFAULT_IFACE>`).

.. code-block:: python

   from getmac import get_default_interface

   try:
       print(get_default_interface())
   except RuntimeError as err:
       print(err)


Settings
========

The settings are attributes of ``getmac.settings``, an instance of :class:`~getmac.variables.Settings`. :ref:`configuration` has a short overview, and this section adds how each one interacts with method selection.

:attr:`~getmac.variables.Settings.FORCE_METHOD`
   The name of a method to use for every lookup, e.g. ``"IpLinkIface"``. The name is looked up in :data:`~getmac.getmac.METHODS`, ignoring case. If no method matches, the lookup logs an error and returns :obj:`None`. On the command line, use ``--force-method``.

   - A new instance is created for each lookup, and ``test()`` is never called.
   - ``platforms``, ``method_type`` and ``network_request`` are ignored, and the caches aren't used or changed.
   - There's no fallback, and exceptions raised by the method are not caught.
   - It applies to every lookup type, including ``get_mac_address()`` called with no arguments.
   - For an IPv4 lookup with ``network_request=True``, ``get_mac_address()`` still builds the ``ip4`` cache and sends the UDP packet described in :ref:`module-api-ipv4-network` before calling the forced method. The UDP packet isn't sent if the forced method is ``"CtypesHost"`` or ``"ArpingHost"`` and it's in the ``ip4`` cache, since it sends an ARP request itself.
   - One case differs: forcing ``"ArpFile"`` for an IPv4 lookup with ``network_request=True``. The :class:`~getmac.getmac.ArpFile` instance in the ``ip4`` cache is then tried first, as described in :ref:`module-api-ipv4-network`, and the points above don't apply to that attempt: it uses the cache, exceptions are caught, and a failure removes it from the cache. If that attempt finds a MAC, it's returned, no UDP packet is sent, and the forced method isn't called. Otherwise the UDP packet is sent and a new ArpFile instance runs as described above.

:attr:`~getmac.variables.Settings.OVERRIDE_PLATFORM`
   Override the detected platform identifier to whatever you set, e.g. ``"linux"``. Use ``--override-platform`` on the command line. It's only read when a cache is built, so set it before the first lookup or :ref:`reset the caches <module-api-reset>` afterwards. It only changes which methods are chosen. Other platform-specific behavior in ``get_mac_address()``, such as how the default interface is found on Windows, still follows the detected platform.

:attr:`~getmac.variables.Settings.PORT`
   The UDP port used to populate the ARP table, as described in :ref:`module-api-ipv4-network`.

:attr:`~getmac.variables.Settings.ARP_TIMEOUT`
   How long to keep looking up a host after sending the UDP packet, as described in :ref:`module-api-ipv4-network`. Use ``--arp-timeout`` on the command line.

:attr:`~getmac.variables.Settings.DEBUG`
   How much detail is logged, see :ref:`module-api-logging`.


Adding a custom method
======================

You can add your own methods at runtime, for example to support a command getmac doesn't know about. If the method would be useful to others, consider contributing it to getmac, see :doc:`adding_methods`.

Writing the class
-----------------

The examples below use this method, which always returns the same MAC. Save it as ``my_methods.py``.

.. code-block:: python
   :caption: my_methods.py

   from typing import Optional

   from getmac.getmac import Method


   class FixedMacIface(Method):
       """Always returns the same MAC address. Only useful as an example."""

       platforms = {"linux", "darwin", "windows"}
       method_type = "iface"

       def test(self) -> bool:
           return True

       def get(self, arg: str) -> Optional[str]:
           return "02:00:00:00:00:01"

Requirements to follow for implementing a method:

- ``platforms`` **must** include each platform the method should run on, see :ref:`module-api-platforms`.
- ``method_type`` **must** be one of the values in :ref:`module-api-method-types`.
- Set ``network_request = True`` if ``get()`` can result in network traffic (e.g. an ARP request).
- ``test()`` should be cheap, such as checking that a command or file exists. :func:`~getmac.utils.check_command` and :func:`~getmac.utils.check_path` do this. If it raises, getmac treats it as a failed test.
- ``get()`` should return the MAC as a :class:`str`, or return :obj:`None` if it wasn't found.
- When ``get()`` can't work on this system, it should raise an exception or set ``self.unusable = True``, so that getmac moves on to the next method. See :ref:`module-api-fallback`.
- A ``default_iface`` method returns an interface name, and its ``get()`` is called with an empty string, so define it as ``def get(self, arg: str = "")``.

:mod:`getmac.utils` has helpers for running commands (:func:`~getmac.utils.popen`), reading files (:func:`~getmac.utils.read_file`) and matching output (:func:`~getmac.utils.search`), and :class:`~getmac.variables.Constants` has regular expressions for MAC addresses, such as :attr:`~getmac.variables.Constants.MAC_RE_COLON`.

Here's a more realistic method. It parses the output of ``ip -brief link show dev <iface>``, which looks like ``lo  UNKNOWN  00:00:00:00:00:00 <LOOPBACK,UP,LOWER_UP>``.

.. code-block:: python

   from typing import Optional

   from getmac import utils
   from getmac.getmac import Method
   from getmac.variables import consts


   class IpBriefLinkIface(Method):
       """Get the MAC of an interface from ``ip -brief link show dev <iface>``."""

       platforms = {"linux"}
       method_type = "iface"

       def test(self) -> bool:
           return utils.check_command("ip")

       def get(self, arg: str) -> Optional[str]:
           # If the interface doesn't exist, "ip" exits with code 1, which getmac
           # treats as "not found". Other exit codes make getmac try the next method.
           output = utils.popen("ip", f"-brief link show dev {arg}")
           return utils.search(r"^\S+\s+\S+\s+" + consts.MAC_RE_COLON, output)

Registering it
--------------

Add the class to :data:`~getmac.getmac.METHODS` before the first lookup of its type (e.g. ``"iface"``). The order of :data:`~getmac.getmac.METHODS` is the order methods are tested in, so insert it at the front to make it the primary method:

.. code-block:: python

   from getmac import get_mac_address
   from getmac.getmac import METHODS

   from my_methods import FixedMacIface

   METHODS.insert(0, FixedMacIface)  # Before the first "iface" lookup

   print(get_mac_address(interface="eth0"))

Output:

.. code-block:: text

   02:00:00:00:00:01

If you append it instead, any built-in method of the same type that passes its test comes first, and yours becomes a fallback.

Change the list in place, as above, or replace the module attribute (``getmac.getmac.METHODS = [...]``).

.. _module-api-reset:

If lookups already happened
---------------------------

Adding a method doesn't affect a type whose cache is already built. To make getmac choose again, set that type's entry in :data:`~getmac.getmac.METHOD_CACHE` to :obj:`None` and empty its :data:`~getmac.getmac.FALLBACK_CACHE` list. The next lookup of that type tests :data:`~getmac.getmac.METHODS` again.

.. code-block:: python

   from getmac import get_mac_address
   from getmac.getmac import FALLBACK_CACHE, METHOD_CACHE, METHODS

   from my_methods import FixedMacIface

   print(get_mac_address(interface="lo"))  # Builds the "iface" cache

   METHODS.insert(0, FixedMacIface)
   print(get_mac_address(interface="lo"))  # Still uses the method chosen earlier

   METHOD_CACHE["iface"] = None  # Forget the "iface" selection
   FALLBACK_CACHE["iface"] = []
   print(get_mac_address(interface="lo"))  # METHODS is tested again

Example output on Linux:

.. code-block:: text

   00:00:00:00:00:00
   00:00:00:00:00:00
   02:00:00:00:00:01

To start over completely, reset every type. Also clear :attr:`gvars.DEFAULT_IFACE <getmac.variables.Variables.DEFAULT_IFACE>`, where ``get_mac_address()`` remembers the default interface after the first call without arguments. Without that, a new ``default_iface`` method is never used by ``get_mac_address()``.

.. code-block:: python

   from getmac.getmac import FALLBACK_CACHE, METHOD_CACHE
   from getmac.variables import gvars


   def reset_method_caches() -> None:
       """Forget every method getmac has chosen, and the cached default interface."""
       for method_type in METHOD_CACHE:
           METHOD_CACHE[method_type] = None
           FALLBACK_CACHE[method_type] = []
       gvars.DEFAULT_IFACE = ""

:func:`~getmac.utils.check_command` also caches whether each command exists, in :attr:`gvars.CHECK_COMMAND_CACHE <getmac.variables.Variables.CHECK_COMMAND_CACHE>`. Clear that dict as well if commands were installed or removed since the first lookup.

To undo these changes in tests, see :ref:`module-api-tests`.

Using a method without registering it
-------------------------------------

You can also put an instance straight into :data:`~getmac.getmac.METHOD_CACHE`. This skips :data:`~getmac.getmac.METHODS`, ``test()`` and the platform check. Fallbacks that are already cached are kept, but if that type's cache hadn't been built yet, there are none.

.. code-block:: python

   from getmac import get_mac_address
   from getmac.getmac import METHOD_CACHE

   from my_methods import FixedMacIface

   METHOD_CACHE["iface"] = FixedMacIface()

   print(get_mac_address(interface="eth0"))  # 02:00:00:00:00:01

The instance stays the primary method until it fails and getmac falls back.

Forcing a custom method
-----------------------

``FORCE_METHOD`` only finds methods that are in :data:`~getmac.getmac.METHODS`, so register the method first. Where it is in the list doesn't matter.

.. code-block:: python

   from getmac import get_mac_address, settings
   from getmac.getmac import METHODS

   from my_methods import FixedMacIface

   METHODS.append(FixedMacIface)
   settings.FORCE_METHOD = "FixedMacIface"

   print(get_mac_address(interface="eth0"))  # 02:00:00:00:00:01


Removing a built-in method
==========================

To stop getmac from using a built-in method, for example one that misbehaves on your system, remove it from :data:`~getmac.getmac.METHODS`. As with adding a method, :ref:`reset the type's cache <module-api-reset>` if a lookup of that type already happened.

.. code-block:: python

   from getmac import get_mac_address
   from getmac.getmac import FALLBACK_CACHE, METHOD_CACHE, METHODS, SysIfaceFile

   METHODS.remove(SysIfaceFile)
   METHOD_CACHE["iface"] = None  # Only needed if an "iface" lookup already happened
   FALLBACK_CACHE["iface"] = []

   get_mac_address(interface="lo")
   print(METHOD_CACHE["iface"], [str(m) for m in FALLBACK_CACHE["iface"]])

Example output on Linux:

.. code-block:: text

   FcntlIface ['IpLinkIface']


.. _module-api-tests:

Undoing changes in tests
========================

Changes to :data:`~getmac.getmac.METHODS`, :data:`~getmac.getmac.METHOD_CACHE`, :data:`~getmac.getmac.FALLBACK_CACHE` and settings affect the whole process, so tests that make them should undo them afterwards. With pytest, the built-in ``monkeypatch`` fixture can give each test its own copy of the list and caches, and puts the originals back when the test ends:

.. code-block:: python

   import getmac.getmac as gm
   import pytest
   from getmac import get_mac_address
   from getmac.variables import gvars

   from my_methods import FixedMacIface


   @pytest.fixture
   def isolated_getmac(monkeypatch):
       """Give the test its own METHODS list and empty caches."""
       monkeypatch.setattr(gm, "METHODS", [FixedMacIface, *gm.METHODS])
       monkeypatch.setattr(gm, "METHOD_CACHE", dict.fromkeys(gm.METHOD_CACHE))
       monkeypatch.setattr(gm, "FALLBACK_CACHE", {key: [] for key in gm.FALLBACK_CACHE})
       monkeypatch.setattr(gvars, "DEFAULT_IFACE", "")


   def test_fixed_mac_is_used(isolated_getmac):
       assert get_mac_address(interface="eth0") == "02:00:00:00:00:01"

Use ``monkeypatch.setattr(settings, "FORCE_METHOD", ...)`` in the same way to change a setting for one test.
