==================
Upgrading to 1.0.0
==================

getmac 1.0.0 has a few changes that can break code written for 0.9.x. This page covers what you may need to change in your code or environment. The full list of changes is in the :doc:`changelog`.

Python versions
===============

getmac 1.0.0 requires Python 3.9 or newer, on CPython or PyPy. Support for Python 2.7 through 3.8, Jython, and IronPython was removed. If you're stuck on one of those, pin to an older version, e.g. ``getmac<1.0.0``. :doc:`installation` lists the last version that works with each old Python.

Settings
========

In 0.9.x, the settings were module-level variables in ``getmac.getmac``. In 1.0.0, they're attributes of the ``getmac.settings`` object. If your code changes a setting, you'll need to update it.

.. list-table::
   :header-rows: 1

   * - 0.9.x
     - 1.0.0
   * - ``getmac.getmac.DEBUG``
     - ``getmac.settings.DEBUG``
   * - ``getmac.getmac.PORT``
     - ``getmac.settings.PORT``
   * - ``getmac.getmac.OVERRIDE_PLATFORM``
     - ``getmac.settings.OVERRIDE_PLATFORM``
   * - ``getmac.getmac.FORCE_METHOD``
     - ``getmac.settings.FORCE_METHOD``

For example, this 0.9.x code:

.. code-block:: python

   from getmac import getmac

   getmac.PORT = 44444

becomes:

.. code-block:: python

   from getmac import settings

   settings.PORT = 44444

The platform constants (``WINDOWS``, ``PLATFORM``, etc.) are now attributes of ``getmac.variables.consts``, and the helper functions (``check_command()``, etc.) are in :mod:`getmac.utils`. :doc:`architecture` covers where everything lives.

Exceptions
==========

In 1.0.0, :func:`~getmac.getmac.get_mac_address` raises a :class:`RuntimeError` when no method can do the lookup: either no methods match the type of request and platform, or all of them fail their test (in other words, none of them work). In 0.9.x, getmac logged a critical message, showed a :class:`RuntimeWarning`, and returned :obj:`None`.

This should almost never happen unless you're on an exotic platform or have an unusual configuration (see :doc:`troubleshooting`). If your code has to keep going regardless, catch it:

.. code-block:: python

   from getmac import get_mac_address

   try:
       mac = get_mac_address(interface="eth0")
   except RuntimeError:
       mac = None

:func:`~getmac.getmac.get_mac_address` also raises a :class:`ValueError` for :class:`~ipaddress.IPv4Network` and :class:`~ipaddress.IPv6Network` objects (they're networks, not hosts), and for arguments of an unsupported type.

Removed methods
===============

The ``UuidArpGetnode`` and ``UuidLanscan`` methods were removed. If you set ``FORCE_METHOD`` (or ``--force-method``) to one of them, use :class:`~getmac.getmac.ArpVariousArgs` or :class:`~getmac.getmac.LanscanIface` instead.

Changes in results
==================

Some lookups return different results in 1.0.0:

- ``get_mac_address()`` with no arguments no longer guesses interface names like ``eth0`` or ``en0``, and no longer falls back to the loopback interface's ``00:00:00:00:00:00``. If the default interface can't be found or doesn't have a MAC, the first non-loopback interface with a MAC is used, and :obj:`None` if there isn't one. See :doc:`usage`.
- On Windows, ``get_mac_address()`` with no arguments uses the actual default interface, instead of assuming it's named "Ethernet".
- On Windows, interface names must match the whole name or description (case-insensitive). In 0.9.x, part of a name was enough, so "Wi-Fi" could return the MAC of the "Microsoft Wi-Fi Direct Virtual Adapter".
- On Linux, incomplete, failed, and proxy ARP entries in ``/proc/net/arp`` are ignored, so an IP that's no longer in use returns :obj:`None` instead of a stale MAC.
- Commands that getmac runs are stopped after 15 seconds (:attr:`~getmac.variables.Settings.COMMAND_TIMEOUT`), and the next method is tried. Before, a command that never finished would hang the lookup forever.

Removed packaging
=================

RPM packaging was removed, since it hadn't been maintained since 0.6.0.
