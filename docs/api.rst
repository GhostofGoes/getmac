===
API
===

Full :abbr:`API (application programming interface)` reference for the `getmac` package, split by how much you should rely on it.

**In short:** most people only need :func:`~getmac.get_mac_address`, and maybe :func:`~getmac.get_default_interface` and :data:`~getmac.settings`. Those three are the public API. The rest of this page is internal, and can change between releases.

Public API
==========

These are the names in ``__all__`` that you can import from ``getmac``. ``settings`` is the one instance of :class:`~getmac.variables.Settings`, see :ref:`configuration`. (``consts`` and ``gvars`` are internal, see below.) ``__version__`` is the version string.

.. automodapi:: getmac
   :include-all-objects:
   :no-heading:
   :skip: __version__

Methods and lookup functions
============================

:class:`~getmac.getmac.Method` is the base class of every method, and the built-in methods, the caches (:data:`~getmac.getmac.METHODS`, :data:`~getmac.getmac.METHOD_CACHE` and :data:`~getmac.getmac.FALLBACK_CACHE`), and the lower-level lookup functions are all here. :doc:`platforms` lists the methods for each platform and lookup type, in the order they're tried. :doc:`module_api` explains how one is selected.

.. automodapi:: getmac.getmac
   :include-all-objects:
   :no-heading:
   :skip: CalledProcessError,IPv4Address,IPv4Interface,IPv4Network,IPv6Address,IPv6Interface,IPv6Network,ip_address,Final,Optional,Union,consts,gvars,settings,IFCONFIG_REGEX,get_mac_address,get_default_interface

Internals
=========

.. warning::
   Most of what this page describes lives in :mod:`getmac.getmac` and is an internal API that may change between releases. Use it with care.

:mod:`getmac.variables` and :mod:`getmac.utils` are internal and may change between releases. They're documented because the methods use them, and because :doc:`custom_methods` imports from them.

.. automodapi:: getmac.variables
   :no-heading:
   :skip: VarsClass

.. automodapi:: getmac.utils
   :no-heading:
