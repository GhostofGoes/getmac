==============================
Customizing methods at runtime
==============================

.. warning::
   Most of what this page describes lives in :mod:`getmac.getmac` and is an internal API that may change between releases. Use it with care.

This page covers changing which methods getmac uses, from your own code: adding a method, removing a built-in one, and undoing your changes in tests. :doc:`module_api` explains how methods are chosen, which is worth reading first, and :doc:`architecture` has a :ref:`"Where things live" <architecture-where>` section on what to import from where.

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

Things the example doesn't show:

- Set ``network_request = True`` if ``get()`` can result in network traffic (e.g. an ARP request).
- Keep ``test()`` cheap, such as checking that a command or file exists. If it raises, getmac treats it as a failed test.
- Return :obj:`None` from ``get()`` when the MAC wasn't found. If it can't work on this system, raise an exception or set ``self.unusable = True`` instead, so getmac moves on to the next method (see :ref:`module-api-fallback`).
- A ``default_iface`` method's ``get()`` is called with an empty string, so define it as ``def get(self, arg: str = "")``.

The rest of the rules, like the ``platforms`` and ``method_type`` values, are in :ref:`module-api-platforms` and :ref:`module-api-method-types`. The "Write the method" section of :doc:`adding_methods` goes through them in more detail, and applies to methods kept in your own code too (outside ``getmac.py``, you import ``utils`` and ``consts`` yourself, as the example below does).

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


.. _module-api-removing-method:

Removing a built-in method
==========================

To stop getmac from using a built-in method, for example one that misbehaves on your system, remove it from :data:`~getmac.getmac.METHODS`. As with adding a method, :ref:`reset the type's cache <module-api-reset>` if a lookup of that type already happened. On the command line, use ``--exclude-method`` (see :doc:`cli`).

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
