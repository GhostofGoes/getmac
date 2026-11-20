======================
Command-Line Interface
======================

The ``getmac`` command is primarily provided to enable debugging and troubleshooting of ``getmac``. It also provides a handy cross-platform command line tool to get :term:`MAC addresses <MAC address>`, in case you needed one. It's installed along with ``getmac`` when pip installed, and can be invoked as long as your Python's ``Scripts`` folder is on your PATH.

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

   # Print the name of the default network interface (e.g. "eth0"), instead of a MAC
   getmac --default-interface
   getmac -D

Only one of ``--interface``, ``--ip``, ``--ip6``, ``--hostname``, ``--default-interface``, and ``--list-methods`` can be used at a time.

Write each option in full, for example ``--interface`` and not ``--int``. If you write only the start of an option, the error names the options that start with it. If an option, a method name, or a platform name has a typo, the error suggests the closest one.


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
- ``1``: getmac found nothing, and printed nothing.
- ``2``: the arguments are invalid or conflict (e.g. ``-i`` with ``-4``). The usage message goes to stderr.
- ``3``: the lookup failed with an error. For example, there are no methods for the platform, or none of them work. getmac prints the error to stderr as ``getmac: error: ...``. With ``-d``, it also prints the traceback. getmac also exits with ``3`` if it cannot write to stdout. If the reader of a pipe closed it (for example, ``getmac | head -1``), there is no error message.
- ``130``: you stopped getmac with :kbd:`Ctrl-C`. On Linux, macOS, and other Unix-like systems, getmac ends with the SIGINT signal, and the shell reports ``130``. A loop or a script in the shell then also stops.

getmac prints warnings to stderr as ``getmac: warning: ...``.

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

If getmac finds nothing (exit code ``1``), use ``-v`` to see the cause.


JSON output
-----------

``--json`` prints the result as JSON, with the method that found it and the platform. The output is one line. If stdout is a terminal, the output is indented. If getmac finds nothing, ``mac`` is ``null`` and the exit code is ``1``. If there is an error (exit code ``3``), getmac prints nothing to stdout.

.. code-block:: shell

   $ getmac --json -i eth0
   {"mac": "00:0c:29:b5:72:37", "lookup": "interface", "target": "eth0", "method": "SysIfaceFile", "platform": "linux"}

``lookup`` is ``interface``, ``ip``, ``ip6``, ``hostname``, or ``default`` (no arguments). ``target`` is the value that you gave for the lookup (``null`` for ``default``). ``method`` is ``null`` if getmac used no method, for example for ``localhost``.

With ``--default-interface``, the result is the name of the interface:

.. code-block:: shell

   $ getmac --json -D
   {"interface": "eth0", "method": "DefaultIfaceLinuxRouteFile", "platform": "linux"}

With ``--list-methods``, each type of lookup has a list of its methods, in the order that getmac tries them. The ``status`` is ``primary``, ``fallback``, ``failed`` (the test of the method failed), or ``skipped`` (the method sends packets, and ``--no-net`` is set).

.. code-block:: shell

   $ getmac --json --list-methods
   {"platform": "linux", "methods": {"ip4": [{"name": "ArpFile", "status": "primary"}, ...], ...}}


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

To stop getmac from using a method, for example one that gives a wrong result on your system, use ``--exclude-method`` (``-E``). getmac uses the next method that works instead. To exclude more than one method, give the argument more than once.

.. code-block:: shell

   getmac -i eth0 --exclude-method SysIfaceFile
   getmac --ip 192.168.0.1 -E arpfile -E ipneighborshow

``--list-methods`` shows the methods for each type of lookup on this platform, in the order getmac tries them, and whether each one works here. It tests each method the same way a lookup does (e.g. it checks that a command exists), but it doesn't look anything up.

.. code-block:: shell

   getmac --list-methods

Example output on Linux:

.. code-block:: text

   Platform: linux

   ip4:
     ArpFile                      primary
     ArpingHost                   doesn't work here (test() failed)
     IpNeighborShow               fallback
     ArpVariousArgs               doesn't work here (test() failed)

   ...

getmac uses the ``primary`` method for a lookup. If that method fails, getmac tries the ``fallback`` methods in order (see :ref:`module-api-fallback`). The other options change the list too, such as ``--override-platform``, ``--exclude-method``, and ``--no-net`` (which skips methods that send packets).

You can override the platform that getmac detects with ``--override-platform``. Use it when you debug a problem, or if you know that a method for a different platform works on the current platform. The platforms are the ones in :attr:`Method.platforms <getmac.getmac.Method.platforms>`: ``android``, ``darwin``, ``dragonfly``, ``freebsd``, ``hp-ux``, ``linux``, ``netbsd``, ``openbsd``, ``other``, ``sunos``, ``windows``, and ``wsl``. getmac ignores the case of the name. Any other name is an error. If getmac does not know the platform of a system, it uses the methods for ``other``. To test that case, use ``--override-platform other``.

.. code-block:: shell

   # Force "linux" to be the "detected" platform and use "linux" methods
   getmac -i eth0 --override-platform linux

   # Force "windows" to be the "detected" platform and use "windows" methods
   getmac --ip 192.168.0.1 --override-platform windows


You can also make getmac use one specific method with ``--force-method``. getmac then uses the method even if it does not work on your system. The :doc:`api` lists the method names, and ``--list-methods`` shows the ones for your platform. getmac ignores the case of the name. A name that is not a method, or that is also given to ``--exclude-method``, is an error.

.. code-block:: shell

   getmac -v -dddd --ip 192.168.0.1 --force-method ctypeshost

:doc:`platforms` lists which methods are used on each platform, and :doc:`module_api` explains how they're chosen.


Slow commands
-------------

getmac stops a command that it runs (such as ``arp`` or ``ipconfig.exe``) if it doesn't finish in 15 seconds, and tries the next method. Use ``--command-timeout`` to change how long to wait, in seconds. ``0`` waits for as long as the command takes.

.. code-block:: shell

   getmac --ip 192.168.0.1 --command-timeout 5


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
