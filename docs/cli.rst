======================
Command-Line Interface
======================

The ``getmac`` command provides developers and power users a cross-platform command line tool to get MAC addresses. It is installed when the pip package is installed.

Basic Usage
===========

.. note::
   Depending on your Python environment, you may not be able to run the command directly (e.g. ``getmac``). If this is the case, then it will have to be invoked via the Python interpreter. See :ref:`python-invoke` for details.

.. note::
   On Windows, ``getmac.exe`` is a *system binary* included with Windows. Depending on the value of the ``PATH`` environment variable, it may get prioritized over the ``getmac`` executable shim installed by pip. Ensure the ``\Scripts\`` folder for your Python installation is added to the ``PATH`` variable for your user! Examples: ``C:\Users\<USERNAME>\AppData\Local\Programs\Python\Python39\Scripts``, ``C:\Users\<USERNAME>\scoop\apps\python\current\Scripts``.


.. code-block:: shell

   # Print usage and command line arguments
   getmac --help

   # Print the current version
   getmac --version

   # No arguments returns the MAC address of the default network interface
   getmac

   # Interface names, IPv4/IPv6 addresses, or Hostnames can be specified
   getmac --interface ens33
   getmac --ip 192.168.0.1
   getmac --ip6 ::1
   getmac --hostname home.router


Examples
========

Remote hosts
------------

Getting the MAC address of a remote host requires the ARP table to be populated. By default, getmac will populate the table by sending a UDP packet to a high port on the host (defaults to ``55555``). This can be disabled with ``--no-network-request``, as shown below.

.. code-block:: shell

   getmac --no-network-request --ip 192.168.0.1
   getmac --no-network-request -n home.router



Advanced usage
==============

Controlling method selection
----------------------------
getmac has a selection of methods used to acquire information across platforms. The methods it uses are determined by the platform and if required commands/libraries are present. This system isn't perfect, and in some cases it can be beneficial to have control over method selection, such as in the case of debugging.

The platform detected by getmac can be overridden via ``--override-platform``. This is useful when debugging issues or if you know a method for a different platform works on the current platform. Any values returned by ``platform.system()`` are valid.

.. code-block:: shell

   # Force "linux" to be the "detected" platform and use "linux" methods
   getmac -i eth0 --override-platform linux

   # Force "windows" to be the "detected" platform and use "windows" methods
   getmac --ip 192.168.0.1 --override-platform windows


A specific method can also be used with ``--force-method``, regardless of the consequences or if it even works.

.. code-block:: shell

   getmac -v -dddd --ip 192.168.0.1 --force-method ctypeshost


Enabling logging messages and debugging
---------------------------------------

.. note::
   When reporting an issue or asking for help, please enable verbose and the highest level of debugging: ``getmac -v -dddd [arguments]``

Normally, no log messages are printed, just the result from the command. Adding ``-v`` (``--verbose``) argument to any command will enable these messages. This is useful for debugging issues or understanding what's happening.

.. code-block:: shell

   getmac --verbose
   getmac -v -i eth0
   getmac --verbose --ip 192.168.0.1


There is also a debugging mode. There are multiple levels of debugging, up to 4. Adding ``-d`` (``--debug``) argument argument enables debugging, and additional ``-d`` arguments increase the level of debugging. This argument must be combined with ``-v`` (``--verbose``), otherwise it's useless.

.. code-block:: shell

   # Enable debugging at level 1
   getmac -v -d

   # Example with another argument
   getmac -v -d -i enp11s4

   # Debug level 2 (note the two 'd' characters)
   getmac -v -dd -n home.router

   # Debug level 3
   getmac -v -ddd --ip 192.168.0.1

   # Debug level 4
   getmac -v -dddd -i eth0



.. _python-invoke:

Invoking via interpreter
========================

If ``getmac`` doesn't work, try ``python3 -m getmac``, where ``python3`` is whatever command you use to run Python and used to install the package.

On Windows, this may be ``py``, e.g. ``py -m getmac``, or just ``python``, e.g. ``python -m getmac``.

When invoking in this fashion, replace calls to ``getmac`` in the examples above with ``python3 -m getmac`` (or whatever invocation applies to your platform).

.. tab:: Linux/macOS

   .. code-block:: shell

      python3 -m getmac
      python3 -m getmac --help
      python3 -m getmac --version

.. tab:: Windows

   .. code-block:: shell

      py -m getmac
      py -m getmac --help
      py -m getmac --version


Examples of running as a Python module with shorthands for the arguments

.. tab:: Linux/macOS

   .. code-block:: shell

      python3 -m getmac -i 'Ethernet 4'
      python3 -m getmac -4 192.168.0.1
      python3 -m getmac -6 ::1
      python3 -m getmac -n home.router

.. tab:: Windows

   .. code-block:: shell

      py -m getmac -i 'Ethernet 4'
      py -m getmac -4 192.168.0.1
      py -m getmac -6 ::1
      py -m getmac -n home.router


.. _args:

Arguments reference
===================

.. sphinx_argparse_cli::
   :module: getmac.__main__
   :func: build_parser
