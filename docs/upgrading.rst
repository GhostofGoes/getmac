=====================
Upgrading to 1.0.0
=====================

getmac 1.0.0 has changes that can break code that worked with 0.9.x. This page lists the changes that can need a change to your code or your environment. For the full list of changes, see the :doc:`changelog`.

Python versions
===============

getmac 1.0.0 needs Python 3.9 or newer. It supports CPython and PyPy.

getmac 1.0.0 does not support Python 2.7 to 3.8, Jython, or IronPython. If you must use one of these, pin getmac to an older version, for example ``getmac<1.0.0``. :doc:`installation` lists the last version for each old Python version.

Settings
========

In 0.9.x, the settings were global variables in the ``getmac.getmac`` module. In 1.0.0, the settings are attributes of the ``getmac.settings`` object. If your code changes a setting, you must change your code.

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

For example, change this 0.9.x code:

.. code-block:: python

   from getmac import getmac

   getmac.PORT = 44444

to this 1.0.0 code:

.. code-block:: python

   from getmac import settings

   settings.PORT = 44444

The platform constants, such as ``WINDOWS`` and ``PLATFORM``, are attributes of ``getmac.variables.consts`` in 1.0.0. The helper functions, such as ``check_command``, are in :mod:`getmac.utils`. :doc:`module_api` tells where each item is.

Errors
======

In 1.0.0, :func:`~getmac.getmac.get_mac_address` raises a :class:`RuntimeError` when no method can do the lookup. This occurs when no method agrees with the type of lookup and the platform, or when all those methods fail their test. In 0.9.x, getmac logged a critical message, showed a :class:`RuntimeWarning`, and returned :obj:`None`.

If your code must continue when getmac cannot do a lookup, catch the :class:`RuntimeError`:

.. code-block:: python

   from getmac import get_mac_address

   try:
       mac = get_mac_address(interface="eth0")
   except RuntimeError:
       mac = None

:func:`~getmac.getmac.get_mac_address` also raises a :class:`ValueError` for :class:`~ipaddress.IPv4Network` and :class:`~ipaddress.IPv6Network` objects.

Removed methods
===============

1.0.0 removes the ``UuidArpGetnode`` and ``UuidLanscan`` methods. If you set ``FORCE_METHOD`` or ``--force-method`` to one of these names, use a different method:

- Instead of ``UuidArpGetnode``, use ``ArpVariousArgs``.
- Instead of ``UuidLanscan``, use ``LanscanIface``.

Changes in the results
======================

Some lookups give different results in 1.0.0:

- ``get_mac_address()`` with no arguments does not guess interface names such as ``eth0`` or ``en0``. It also does not return ``00:00:00:00:00:00`` from the loopback interface. See :ref:`usage-errors` and the notes in :doc:`usage`.
- On Windows, ``get_mac_address()`` with no arguments uses the real default interface. It does not assume that the interface name is "Ethernet".
- On Windows, an interface name must be the same as the full name or description of the interface. Case is not important. In 0.9.x, a part of the name was sufficient. For example, "Wi-Fi" could return the MAC of the "Microsoft Wi-Fi Direct Virtual Adapter".
- On Linux, ``get_mac_address()`` ignores incomplete, failed and proxy ARP entries in ``/proc/net/arp``. For these entries, it now returns :obj:`None`.

Removed packaging
=================

1.0.0 does not include RPM packaging.
