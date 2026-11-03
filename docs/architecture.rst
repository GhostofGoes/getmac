============
Architecture
============

This page explains how getmac's code is organized, and a few of the design decisions behind it. For how methods work in detail, see :doc:`module_api`, and for how to add one, see :doc:`adding_methods`.


Where things live
=================

getmac is a small package with a handful of modules:

- ``getmac`` (``__init__.py``): the public API. :func:`~getmac.getmac.get_mac_address`, :func:`~getmac.getmac.get_default_interface`, ``settings``, and ``__version__`` are the names in ``__all__``. Nothing else is imported into the top-level package.
- :mod:`getmac.getmac`: the :class:`~getmac.getmac.Method` base class, every built-in method, the :data:`~getmac.getmac.METHODS` list, the :data:`~getmac.getmac.METHOD_CACHE` and :data:`~getmac.getmac.FALLBACK_CACHE` dicts, and lower-level functions such as :func:`~getmac.getmac.get_by_method` and :func:`~getmac.getmac.initialize_method_cache`.
- :mod:`getmac.variables`: the ``settings``, ``consts`` and ``gvars`` objects (see below), documented as the :class:`~getmac.variables.Settings`, :class:`~getmac.variables.Constants` and :class:`~getmac.variables.Variables` classes.
- :mod:`getmac.utils`: helper functions used by methods, such as :func:`~getmac.utils.popen` for running commands and :func:`~getmac.utils.search` for matching their output.
- ``getmac.__main__``: the command line interface (:doc:`cli`), a thin ``argparse`` wrapper around :func:`~getmac.getmac.get_mac_address`.

``Method`` isn't exported from the top-level package, so import it with ``from getmac.getmac import Method``.


How a lookup works
==================

getmac doesn't use C-extensions or call platform APIs directly. That's the whole point: pure Python, no dependencies, runs everywhere. Instead, it gets MACs the way a sysadmin would: by running commands like ``arp``, ``ip``, ``ifconfig`` and ``ipconfig.exe``, reading files like ``/proc/net/arp``, and parsing the output with regular expressions. A few methods use standard library features like :mod:`fcntl` and :mod:`ctypes`.

Each of these techniques is a *method*: a subclass of :class:`~getmac.getmac.Method` that declares which platforms it works on and what type of lookup it does, with a cheap ``test()`` ("is the ``ip`` command installed?") and a ``get()`` that does the actual work. The first time :func:`~getmac.getmac.get_mac_address` needs a type of lookup (say, an interface MAC), it filters :data:`~getmac.getmac.METHODS` down to the methods for that type and this platform, tests them, and caches the first one that passes as the primary method and the rest as fallbacks. If the primary method fails during a lookup, the next fallback takes over. The one-time cost of testing is why the first call is slower than the rest. :doc:`module_api` has all the details.

This replaced the pre-0.9.0 approach of throwing every method at the wall until one stuck, which was slow (a miss could take seconds), prone to false positives, and hard to test. The `rewrite summary <https://github.com/GhostofGoes/getmac/blob/main/docs/misc_docs/rewrite.md>`__ from the 0.9.0 release has the full story.


Singleton classes for global state
==================================

All of getmac's global state lives in one module, :mod:`getmac.variables`, as attributes of three classes that are each instantiated exactly once:

- ``settings`` (:class:`~getmac.variables.Settings`): user-configurable options, such as :attr:`~getmac.variables.Settings.DEBUG` and :attr:`~getmac.variables.Settings.PORT`.
- ``consts`` (:class:`~getmac.variables.Constants`): platform detection results that don't change after import, such as :attr:`~getmac.variables.Constants.WINDOWS` and :attr:`~getmac.variables.Constants.PLATFORM`.
- ``gvars`` (:class:`~getmac.variables.Variables`): everything else that changes at runtime, such as :attr:`~getmac.variables.Variables.PATH` and :attr:`~getmac.variables.Variables.CHECK_COMMAND_CACHE`.

``getmac.py``, ``utils.py`` and ``__main__.py`` all import the same three objects (``from .variables import consts, gvars, settings``), so every module reads and writes one shared copy of each value, instead of each module keeping its own.

Why objects, instead of the module-level variables that 0.9.x used?

- **No** ``global`` **keyword.** Code changes an attribute (``gvars.DEFAULT_IFACE = ...``) instead of rebinding a module-level name, so functions don't need ``global`` declarations.
- **Changes are seen everywhere.** When you set ``settings.DEBUG = 2`` (or the CLI does, from ``--debug``), all of getmac sees it. A module-level variable copied with ``from ... import DEBUG`` would keep its old value in every module that imported it.
- **Tests are simpler.** One patch, such as ``mocker.patch.object(consts, "WINDOWS", True)``, changes the value everywhere it's used, and is undone automatically when the test ends.
- **Better docs.** Each attribute has a type annotation and a docstring, and the classes are rendered in the :doc:`api`, which makes it clear which values are settings for users to change and which are internal.
- **Room to grow.** An attribute can become a property that validates or lazily computes its value, and the singletons could later be replaced by instances passed to functions (as planned for :attr:`~getmac.variables.Settings.OVERRIDE_PLATFORM`), without changing the ``settings.NAME`` style of access in the code that uses them.
