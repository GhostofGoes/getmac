======================
Command-Line Interface
======================

The ``getmac`` command provides developers and power users a cross-platform command line tool to get :term:`MAC addresses <MAC address>`. It is installed when the pip package is installed.

Basic Usage
===========

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
   getmac --ip6 fe80::1
   getmac --hostname home.router

   # The same, with the short forms of the arguments
   getmac -i ens33
   getmac -4 192.168.0.1
   getmac -6 fe80::1
   getmac -n home.router

Only one of ``--interface``, ``--ip``, ``--ip6``, and ``--hostname`` can be used at a time.


.. _python-invoke:

Running it through Python
=========================

If ``getmac`` doesn't work, try ``python3 -m getmac``, where ``python3`` is whatever command you use to run Python and used to install the package. That happens when your Python environment doesn't have the command on the ``PATH``. It also happens on Windows, where ``getmac`` can run Windows' own ``getmac.exe`` instead (if it prints a table that looks nothing like getmac's, that's why). See :doc:`troubleshooting`.

On Windows, this may be ``py``, e.g. ``py -m getmac``, or just ``python``, e.g. ``python -m getmac``.

When invoking in this fashion, replace calls to ``getmac`` in the examples on this page with ``python3 -m getmac`` (or whatever invocation applies to your platform).

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


Output and exit codes
=====================

- ``0``: the MAC was printed to stdout (also for ``--help`` and ``--version``).
- ``1``: nothing was found, or every method failed, and nothing is printed. An uncaught :class:`RuntimeError` is a traceback, and exits with ``1`` too.
- ``2``: the arguments are invalid or conflict (e.g. ``-i`` with ``-4``). The usage message goes to stderr.

Log messages (``-v``) go to stderr, so stdout only ever has the MAC. This makes it easy to use in scripts:

.. tab:: Linux/macOS

   .. code-block:: shell

      if mac=$(getmac -i eth0); then
          echo "Found: $mac"
      else
          echo "No MAC found" >&2
      fi

.. tab:: Windows

   .. code-block:: powershell

      $mac = py -m getmac -i "Ethernet 3"
      if ($LASTEXITCODE -eq 0) { "Found: $mac" } else { "No MAC found" }

Nothing found and a lookup that failed look the same (exit code ``1``, no output). Use ``-v`` to see why.


Remote hosts
============

Getting the MAC address of a :term:`remote host` requires the :term:`ARP table` (IPv4) or :term:`NDP table` (IPv6) to be populated. By default, getmac gets the host into the table with an ARP request (IPv4 only, on Windows or if ``arping`` is installed) or, if it can't, an empty :term:`UDP` packet to a high port on the host (defaults to ``55555``). On Linux, it reads the ARP table file first, and sends nothing if the host is already there. This can be disabled with ``--no-net`` (or ``-N``), as shown below.

.. code-block:: shell

   getmac --no-net --ip 192.168.0.1
   getmac -N -n home.router

The host's entry is only added to the table once it replies, which can take longer than getmac takes to check the table. Use ``--arp-timeout`` to keep checking for it for up to a number of seconds (by default, it's checked once).

.. code-block:: shell

   getmac --ip 192.168.0.1 --arp-timeout 1

The UDP port can be changed with ``--override-port``.

.. code-block:: shell

   getmac --ip 192.168.0.1 --override-port 9001

:ref:`usage-remote-hosts` has the details, and :ref:`troubleshooting-remote-none` covers what to do when a host isn't found.


Troubleshooting options
=======================

Logging and debugging
---------------------

.. note::
   When reporting an issue or asking for help, please enable verbose and the highest level of debugging: ``getmac -v -dddd [arguments]``

Normally, no log messages are printed, just the result from the command. Adding the ``-v`` (``--verbose``) argument to any command will enable these messages. This is useful for debugging issues or understanding what's happening.

.. code-block:: shell

   getmac --verbose
   getmac -v -i eth0
   getmac --verbose --ip 192.168.0.1


There is also a debugging mode. There are multiple levels of debugging, up to 4. Adding the ``-d`` (``--debug``) argument enables debugging, and additional ``-d`` arguments increase the level of debugging. ``-d`` turns on the log messages too, so ``-v`` is optional when it's used.

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

Level 2 shows which methods were considered and which one was chosen, and level 4 shows every command that was run and its output. The levels are described in :ref:`usage-logging`.


Controlling method selection
----------------------------

getmac has a selection of methods used to acquire information across platforms. The methods it uses are determined by the platform and if required commands/libraries are present. This system isn't perfect, and in some cases it can be beneficial to have control over method selection, such as in the case of debugging.

The platform detected by getmac can be overridden via ``--override-platform``. This is useful when debugging issues or if you know a method for a different platform works on the current platform. Any value returned by ``platform.system()`` is valid.

.. code-block:: shell

   # Force "linux" to be the "detected" platform and use "linux" methods
   getmac -i eth0 --override-platform linux

   # Force "windows" to be the "detected" platform and use "windows" methods
   getmac --ip 192.168.0.1 --override-platform windows


A specific method can also be used with ``--force-method``, regardless of the consequences or if it even works. The method names are listed in the :doc:`api` (case doesn't matter).

.. code-block:: shell

   getmac -v -dddd --ip 192.168.0.1 --force-method ctypeshost

:doc:`platforms` lists which methods are used on each platform, and :doc:`module_api` explains how they're chosen.


.. _args:

Arguments reference
===================

.. sphinx_argparse_cli::
   :module: getmac.__main__
   :func: build_parser


Environment
===========

``ARP_PATH``
   The file to read the ARP table from, instead of ``/proc/net/arp``. Linux only. See :ref:`usage-environment` for this and the other environment variables getmac uses.
