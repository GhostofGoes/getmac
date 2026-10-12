====================
Using the module API
====================

:func:`~getmac.getmac.get_mac_address` is sufficient for most uses of getmac. This page is about the internal methods that getmac uses to find MAC addresses on different platforms.

Internally, getmac selects a *method* for each type of lookup. A method is a class that uses one technique to find a MAC address. Examples are to read ``/sys/class/net/<iface>/address`` and to run ``ip neighbor show``. This page explains how methods work, and how to write a new method.

.. warning::
   Most of the items on this page are in :mod:`getmac.getmac`. They are an internal API, and they can change between releases. Use them carefully.


Where things live
=================

- ``getmac``: :func:`~getmac.getmac.get_mac_address`, :func:`~getmac.getmac.get_default_interface`, ``settings`` and ``__version__`` (the names in ``__all__``). getmac imports nothing else into the top-level package.
- :mod:`getmac.getmac`: the :class:`~getmac.getmac.Method` base class, the built-in methods, the :data:`~getmac.getmac.METHODS` list, the :data:`~getmac.getmac.METHOD_CACHE` and :data:`~getmac.getmac.FALLBACK_CACHE` dicts, and lower-level functions such as :func:`~getmac.getmac.get_by_method` and :func:`~getmac.getmac.initialize_method_cache`.
- :mod:`getmac.variables`: the ``settings``, ``consts`` and ``gvars`` objects, documented as the :class:`~getmac.variables.Settings`, :class:`~getmac.variables.Constants` and :class:`~getmac.variables.Variables` classes.
- :mod:`getmac.utils`: helper functions used by methods, such as :func:`~getmac.utils.popen` and :func:`~getmac.utils.search`.

The top-level package does not export ``Method``. Import it with ``from getmac.getmac import Method``. The :doc:`api` reference lists each built-in method and its docstring.


Methods 101
===========

Methods
-------

A method is a subclass of :class:`~getmac.getmac.Method`. It must set 3 attributes:

- :attr:`~getmac.getmac.Method.platforms`: a set with the platforms it works on, such as ``{"linux", "darwin"}``.
- :attr:`~getmac.getmac.Method.method_type`: the type of lookup that it does (see below).
- :attr:`~getmac.getmac.Method.network_request`: whether the method sends traffic on the network.

A method overrides two functions:

- :meth:`~getmac.getmac.Method.test`: a fast check that the method can work on this system. An example is "is the ``ip`` command installed?"
- :meth:`~getmac.getmac.Method.get`: does the lookup. It takes one argument, and returns the result or :obj:`None`. The meaning of the argument changes with the method type. For example, the argument of an interface method is the interface name, such as ``"eth0"``.

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
   ``get_mac_address()`` with no arguments does a ``default_iface`` lookup. Then it does an ``iface`` lookup of the interface that it found. If getmac cannot find the default interface, or the default interface has no MAC, getmac uses a different interface. It uses the first interface from :func:`socket.if_nameindex` that has a MAC and is not a loopback interface. Windows is an exception to this.

   On Windows with ``network_request=True`` (the default), getmac first gets the IP address of the interface with the default route. It uses :func:`~getmac.utils.fetch_ip_using_dns` for this. Then it does an ``ip4`` lookup of that address. getmac does the ``default_iface`` lookup only if that lookup does not find a MAC.

.. note::
   There is one cache per lookup type: ``ip4``, ``ip6``, ``iface`` and ``default_iface``.

.. _module-api-platforms:

Platforms
---------

The platform is a lowercase identifier, :attr:`consts.PLATFORM <getmac.variables.Constants.PLATFORM>`. :attr:`settings.OVERRIDE_PLATFORM <getmac.variables.Settings.OVERRIDE_PLATFORM>` replaces it if you set it. To see the platform that getmac detects on your system:

.. code-block:: python

   from getmac.variables import consts

   print(consts.PLATFORM)  # For example, "linux"

The identifiers used by the built-in methods are listed in :attr:`Method.VALID_PLATFORM_NAMES <getmac.getmac.Method.VALID_PLATFORM_NAMES>`.

The platform ``"other"`` is for general methods that getmac can try on unknown systems. getmac uses them only as a last option, when no method agrees with the current platform.

.. _module-api-choosing:

Choosing a method
-----------------

At the first lookup of a type (for example, ``ip4``), :func:`~getmac.getmac.initialize_method_cache` builds the cache for that type. It does these steps:

1. Select the methods in :data:`~getmac.getmac.METHODS` that have the same ``method_type``.
2. Select the methods whose ``platforms`` set includes the current platform. If no method agrees, select the methods for ``"other"`` (see the section above).
3. If ``network_request=False``, remove the methods that have ``network_request=True``.
4. Make an instance of each selected method, and call its ``test()``. The first method that passes (returns :obj:`True`) becomes the *primary* method. getmac keeps it in :data:`METHOD_CACHE[type] <getmac.getmac.METHOD_CACHE>`. The other methods that pass become *fallbacks*. getmac keeps them, in order, in :data:`FALLBACK_CACHE[type] <getmac.getmac.FALLBACK_CACHE>`. getmac does not keep the methods whose ``test()`` returns :obj:`False` or raises an exception.

:func:`~getmac.getmac.initialize_method_cache` raises :class:`RuntimeError` if:

- No method has the requested type.
- No method suits the platform, even after trying ``"other"``.
- Every candidate method fails its ``test()``.

.. note::
   getmac builds the cache at the first lookup, and uses it until the process stops. getmac does not test the methods again. Thus, after the cache of a type exists, these changes have no effect on that type:

   - Changes to :data:`~getmac.getmac.METHODS`
   - Changes to ``OVERRIDE_PLATFORM``
   - Changes to the system, such as a new command

.. _module-api-fallback:

Falling back during a lookup
----------------------------

Each lookup calls ``get()`` on the primary method from the cache. Then:

- If ``get()`` returns a value, that value is the result.
- If ``get()`` returns :obj:`None`, the result is :obj:`None`. getmac does **not** try the fallbacks. :obj:`None` means "not found", for example "this interface does not exist". It does *not* mean "this method does not work".
- If ``get()`` raises an exception, getmac removes the method from the cache. getmac also does this if ``get()`` sets ``self.unusable = True`` and returns :obj:`None`. The first fallback becomes the primary method, and getmac does the lookup again with it, with the same argument. getmac logs the exception as a warning, and does not raise it.
- A :class:`~subprocess.CalledProcessError` with exit code 1 has the same result as :obj:`None`. Many commands exit with code 1 when the interface or host does not exist. All other exit codes are failures, and cause a fallback.
- With ``network_request=False``, getmac skips the methods that send network requests (their ``network_request`` attribute is :obj:`True`). It skips them for the lookup and as fallbacks. They stay in the cache, because a lookup that permitted them may have built the cache.

.. _module-api-ipv4-network:

IPv4 lookups and network requests
---------------------------------

This section applies when :func:`~getmac.getmac.get_mac_address` looks up an IPv4 address (``ip=`` or ``hostname=``) with ``network_request=True`` (the default). Before the lookup, getmac tries to put the host in the ARP table of the system:

1. If :class:`~getmac.getmac.ArpFile` is in the ``ip4`` cache, getmac tries it first, because it is fast to read ``/proc/net/arp``. If it fails, getmac removes it from the cache. getmac does not try another method yet.
2. If not, and :class:`~getmac.getmac.CtypesHost` or :class:`~getmac.getmac.ArpingHost` is in the ``ip4`` cache, it becomes the primary method. These methods send an ARP request themselves.
3. If neither step applies, getmac sends an empty UDP packet to the host. The packet goes to the port in :attr:`settings.PORT <getmac.variables.Settings.PORT>`. The packet causes the system to populate the ARP table.

Then getmac looks up the host with the ``ip4`` cache. If getmac sent the UDP packet and did not find the host, getmac looks up the host again. It stops when it finds the host, or when :attr:`settings.ARP_TIMEOUT <getmac.variables.Settings.ARP_TIMEOUT>` seconds pass. By default, getmac does not look up the host again.

IPv6 lookups send the UDP packet and use ``ARP_TIMEOUT`` in the same way. IPv6 lookups have no ``ArpFile`` step and no ARP request step.


Seeing which methods are used
=============================

Inspecting the caches
---------------------

After a lookup, the caches show the methods that getmac selected. :class:`str` converts a method instance to its class name.

.. code-block:: python

   from getmac import get_mac_address
   from getmac.getmac import FALLBACK_CACHE, METHOD_CACHE

   # Do a lookup, to populate the caches
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

Two helper functions find methods by name:

- :func:`~getmac.getmac.get_instance_from_cache` returns the cached *instance* of a method, primary or fallback, for one lookup type. The name must be the same as the class name, with the same case. For example: ``get_instance_from_cache("iface", "SysIfaceFile")``.
- :func:`~getmac.getmac.get_method_by_name` returns the *class* with a given name from :data:`~getmac.getmac.METHODS`. It ignores case. ``FORCE_METHOD`` uses this function to find a method.

.. _module-api-logging:

Logging and debug output
------------------------

getmac logs to the ``getmac`` logger of the Python :mod:`logging` module. It attaches a :class:`~logging.NullHandler` to that logger. Thus, you see no messages until you configure logging. :attr:`settings.DEBUG <getmac.variables.Settings.DEBUG>` controls the quantity of detail in the log:

- ``0`` (the default): warnings, errors, and some debug messages. For example, a message when getmac builds a cache, and the raw MAC that getmac found.
- ``1``: failed tests, the contents of the caches, each ``get()`` attempt, and the duration of the lookup.
- ``2``: the methods left after filtering by type, by platform, and by ``test()``.
- ``3``: each command that getmac runs.
- ``4``: the output of each command, and the full :data:`~getmac.getmac.METHODS` list.

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

The same command on the command line is ``getmac -v -dd -i lo``. See :doc:`cli`.


Calling lookups directly
========================

get_by_method()
---------------

:func:`~getmac.getmac.get_by_method` does one lookup of a given type, for example ``"ip4"``. It uses the caches and fallbacks that the sections above describe.

It returns the value from ``get()`` of the method. It does not clean the value, as :func:`~getmac.getmac.get_mac_address` does. Many built-in methods return the MAC in the format that the command printed. To get a lowercase MAC with colons, use :func:`~getmac.utils.clean_mac` on the result. This is the same format that :func:`~getmac.getmac.get_mac_address` returns.

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

More information:

- An empty argument returns :obj:`None` and logs an error. ``default_iface`` methods are an exception, because they take no argument.
- It raises :class:`RuntimeError` when getmac can use no method. :ref:`module-api-choosing` describes when this occurs.
- Its ``network_request`` argument has the same effect as in :func:`~getmac.getmac.initialize_method_cache`. The argument has an effect **only if the cache of that type does not exist yet**.

get_default_interface()
-----------------------

:func:`~getmac.getmac.get_default_interface` is the same as ``get_by_method("default_iface")``. Thus, it can also raise :class:`RuntimeError`. ``get_mac_address()`` keeps the default interface between calls, in :attr:`gvars.DEFAULT_IFACE <getmac.variables.Variables.DEFAULT_IFACE>`. ``get_default_interface()`` does not change that value.

.. code-block:: python

   from getmac import get_default_interface

   try:
       print(get_default_interface())
   except RuntimeError as err:
       print(err)


Settings
========

The settings are attributes of ``getmac.settings``, an instance of :class:`~getmac.variables.Settings`. :ref:`configuration` gives a short summary. This section tells how each setting changes the method selection.

:attr:`~getmac.variables.Settings.FORCE_METHOD`
   The name of a method to use for each lookup, for example ``"IpLinkIface"``. getmac finds the name in :data:`~getmac.getmac.METHODS`, and ignores case. If no method has that name, the lookup logs an error and returns :obj:`None`. On the command line, use ``--force-method``.

   - getmac makes a new instance for each lookup. It never calls ``test()``.
   - getmac ignores ``platforms``, ``method_type`` and ``network_request``. It does not use or change the caches.
   - There is no fallback. getmac does not catch the exceptions that the method raises.
   - The setting applies to all lookup types. This includes ``get_mac_address()`` with no arguments.
   - For an IPv4 lookup with ``network_request=True``, ``get_mac_address()`` still builds the ``ip4`` cache. It also sends the UDP packet that :ref:`module-api-ipv4-network` describes, before it calls the forced method. The forced methods ``"CtypesHost"`` and ``"ArpingHost"`` are an exception, if they are in the ``ip4`` cache. These methods send an ARP request themselves, so getmac does not send the UDP packet.
   - The forced method ``"ArpFile"``, for an IPv4 lookup with ``network_request=True``, is a special case. getmac first tries the :class:`~getmac.getmac.ArpFile` instance in the ``ip4`` cache, as :ref:`module-api-ipv4-network` describes. The points above do not apply to that attempt. That attempt uses the cache, getmac catches its exceptions, and a failure removes it from the cache. If that attempt finds a MAC, getmac returns the MAC. getmac then does not send a UDP packet, and does not call the forced method. If that attempt finds no MAC, getmac sends the UDP packet. Then a new ArpFile instance runs, as the points above describe.

:attr:`~getmac.variables.Settings.OVERRIDE_PLATFORM`
   Replaces the detected platform identifier with your value, for example ``"linux"``. On the command line, use ``--override-platform``. getmac reads this setting only when it builds a cache. Thus, set it before the first lookup, or :ref:`reset the caches <module-api-reset>` after you set it. The setting changes only the method selection. Other platform-specific behavior in ``get_mac_address()`` still uses the detected platform. An example is how getmac finds the default interface on Windows.

:attr:`~getmac.variables.Settings.PORT`
   The UDP port used to populate the ARP table, as described in :ref:`module-api-ipv4-network`.

:attr:`~getmac.variables.Settings.ARP_TIMEOUT`
   The maximum time that getmac looks up a host again after it sends the UDP packet. See :ref:`module-api-ipv4-network`. On the command line, use ``--arp-timeout``.

:attr:`~getmac.variables.Settings.DEBUG`
   The quantity of detail in the log. See :ref:`module-api-logging`.


Adding a custom method
======================

You can add your own methods at runtime. For example, you can add a method for a command that getmac does not use. If the method can help other users, please think about adding it to getmac. See :doc:`adding_methods`.

Writing the class
-----------------

The examples below use this method. It always returns the same MAC. Save it as ``my_methods.py``.

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

A method must obey these rules:

- ``platforms`` **must** include each platform that the method can run on. See :ref:`module-api-platforms`.
- ``method_type`` **must** be one of the values in :ref:`module-api-method-types`.
- Set ``network_request = True`` if ``get()`` can send traffic on the network, for example an ARP request.
- ``test()`` must be fast. For example, it can check that a command or file exists. :func:`~getmac.utils.check_command` and :func:`~getmac.utils.check_path` do these checks. If ``test()`` raises an exception, getmac records a failed test.
- ``get()`` must return the MAC as a :class:`str`. If it does not find the MAC, it must return :obj:`None`.
- If ``get()`` cannot work on this system, it must raise an exception or set ``self.unusable = True``. getmac then tries the next method. See :ref:`module-api-fallback`.
- A ``default_iface`` method returns an interface name. getmac calls its ``get()`` with an empty string. Thus, define it as ``def get(self, arg: str = "")``.

:mod:`getmac.utils` has helper functions:

- :func:`~getmac.utils.popen` runs commands.
- :func:`~getmac.utils.read_file` reads files.
- :func:`~getmac.utils.search` finds a match in the output.

:class:`~getmac.variables.Constants` has regular expressions for MAC addresses, such as :attr:`~getmac.variables.Constants.MAC_RE_COLON`.

The next method is more realistic. It parses the output of ``ip -brief link show dev <iface>``. An example of this output is ``lo  UNKNOWN  00:00:00:00:00:00 <LOOPBACK,UP,LOWER_UP>``.

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

Add the class to :data:`~getmac.getmac.METHODS` before the first lookup of its type, for example ``"iface"``. getmac tests the methods in the order of :data:`~getmac.getmac.METHODS`. To make your method the primary method, put it at the start of the list:

.. code-block:: python

   from getmac import get_mac_address
   from getmac.getmac import METHODS

   from my_methods import FixedMacIface

   METHODS.insert(0, FixedMacIface)  # Before the first "iface" lookup

   print(get_mac_address(interface="eth0"))

Output:

.. code-block:: text

   02:00:00:00:00:01

If you add it at the end of the list, the built-in methods of the same type that pass their test come first. Your method then becomes a fallback.

You can change the list in place, as in the example above. You can also replace the module attribute (``getmac.getmac.METHODS = [...]``).

.. _module-api-reset:

If lookups already happened
---------------------------

A new method has no effect on a type whose cache already exists. To make getmac select again, do these steps:

1. Set the entry of that type in :data:`~getmac.getmac.METHOD_CACHE` to :obj:`None`.
2. Set its list in :data:`~getmac.getmac.FALLBACK_CACHE` to an empty list.

The next lookup of that type tests :data:`~getmac.getmac.METHODS` again.

.. code-block:: python

   from getmac import get_mac_address
   from getmac.getmac import FALLBACK_CACHE, METHOD_CACHE, METHODS

   from my_methods import FixedMacIface

   print(get_mac_address(interface="lo"))  # Builds the "iface" cache

   METHODS.insert(0, FixedMacIface)
   print(get_mac_address(interface="lo"))  # Still uses the method that getmac selected before

   METHOD_CACHE["iface"] = None  # Forget the "iface" selection
   FALLBACK_CACHE["iface"] = []
   print(get_mac_address(interface="lo"))  # METHODS is tested again

Example output on Linux:

.. code-block:: text

   00:00:00:00:00:00
   00:00:00:00:00:00
   02:00:00:00:00:01

To start again fully, reset all types. Also clear :attr:`gvars.DEFAULT_IFACE <getmac.variables.Variables.DEFAULT_IFACE>`. ``get_mac_address()`` keeps the default interface there after the first call without arguments. If you do not clear it, ``get_mac_address()`` never uses a new ``default_iface`` method.

.. code-block:: python

   from getmac.getmac import FALLBACK_CACHE, METHOD_CACHE
   from getmac.variables import gvars


   def reset_method_caches() -> None:
       """Forget every method getmac has chosen, and the cached default interface."""
       for method_type in METHOD_CACHE:
           METHOD_CACHE[method_type] = None
           FALLBACK_CACHE[method_type] = []
       gvars.DEFAULT_IFACE = ""

:func:`~getmac.utils.check_command` also keeps a cache of the commands that exist, in :attr:`gvars.CHECK_COMMAND_CACHE <getmac.variables.Variables.CHECK_COMMAND_CACHE>`. If you installed or removed commands after the first lookup, also clear that dict.

To undo these changes in tests, see :ref:`module-api-tests`.

Using a method without registering it
-------------------------------------

You can also put an instance directly into :data:`~getmac.getmac.METHOD_CACHE`. getmac then does not use :data:`~getmac.getmac.METHODS`, ``test()`` or the platform check. getmac keeps the fallbacks that are already in the cache. If the cache of that type did not exist yet, there are no fallbacks.

.. code-block:: python

   from getmac import get_mac_address
   from getmac.getmac import METHOD_CACHE

   from my_methods import FixedMacIface

   METHOD_CACHE["iface"] = FixedMacIface()

   print(get_mac_address(interface="eth0"))  # 02:00:00:00:00:01

The instance stays the primary method until it fails and getmac falls back.

Forcing a custom method
-----------------------

``FORCE_METHOD`` finds only the methods in :data:`~getmac.getmac.METHODS`. Thus, register the method first. Its position in the list is not important.

.. code-block:: python

   from getmac import get_mac_address, settings
   from getmac.getmac import METHODS

   from my_methods import FixedMacIface

   METHODS.append(FixedMacIface)
   settings.FORCE_METHOD = "FixedMacIface"

   print(get_mac_address(interface="eth0"))  # 02:00:00:00:00:01


Removing a built-in method
==========================

To stop the use of a built-in method, remove it from :data:`~getmac.getmac.METHODS`. For example, do this for a method that gives incorrect results on your system. If a lookup of that type occurred already, :ref:`reset the cache of the type <module-api-reset>`, as when you add a method.

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

Changes to :data:`~getmac.getmac.METHODS`, :data:`~getmac.getmac.METHOD_CACHE`, :data:`~getmac.getmac.FALLBACK_CACHE` and the settings apply to the full process. Thus, a test that makes these changes must undo them after the test. In pytest, the built-in ``monkeypatch`` fixture can give each test its own copy of the list and the caches. At the end of the test, the fixture puts back the original values:

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

To change a setting for one test, use ``monkeypatch.setattr(settings, "FORCE_METHOD", ...)`` in the same way.
