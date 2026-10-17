============
Architecture
============

This page explains design decisions in getmac's code. For how methods work and how to add one, see :doc:`adding_methods`.


Singleton classes for global state
==================================

getmac keeps its global state in one place, :mod:`getmac.variables`, as attributes of three classes that are each instantiated once: ``settings`` (:class:`~getmac.variables.Settings`, user-configurable options such as :attr:`~getmac.variables.Settings.DEBUG` and :attr:`~getmac.variables.Settings.PORT`), ``consts`` (:class:`~getmac.variables.Constants`, platform detection results such as :attr:`~getmac.variables.Constants.WINDOWS` and :attr:`~getmac.variables.Constants.PLATFORM`), and ``gvars`` (:class:`~getmac.variables.Variables`, other values that change at runtime, such as :attr:`~getmac.variables.Variables.PATH` and :attr:`~getmac.variables.Variables.CHECK_COMMAND_CACHE`). ``getmac.py``, ``utils.py`` and ``__main__.py`` all import these same objects with ``from .variables import consts, gvars, settings``, so every file reads and writes one shared copy of each value instead of each module keeping its own.

These objects are used instead of module-level variables. Because code changes an attribute of an object (``gvars.DEFAULT_IFACE = ...``) rather than rebinding a module-level name, functions don't need the ``global`` keyword. For the same reason, a change is seen by every module: a user who sets ``settings.DEBUG = 2`` (or the CLI, from ``--debug``) affects all of getmac, whereas a module-level variable copied with ``from ... import DEBUG`` would keep its old value in the modules that imported it. Tests benefit the same way, since one patch, such as ``mocker.patch.object(consts, "WINDOWS", True)``, changes the value everywhere it's used and is undone automatically afterwards.

Grouping the values into classes also makes them easier to document. Each attribute has a docstring and a type annotation, and the classes are rendered as an API reference (see :doc:`api`), which makes it clear which values are settings for users to change and which are internal. Finally, the classes leave room for future changes without changing the code that uses them: an attribute can become a property that validates its value or computes it lazily, and the singletons could be replaced by instances passed to functions (as planned for :attr:`~getmac.variables.Settings.OVERRIDE_PLATFORM`) while keeping ``settings.NAME``-style access.
