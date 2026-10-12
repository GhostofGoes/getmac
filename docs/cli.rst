======================
Command-Line Interface
======================

The ``getmac`` command gets MAC addresses from the command line, on all supported platforms. It is for developers and power users. ``pip`` installs the command when it installs the package.

Basic Usage
===========

.. note::
   In some Python environments, the ``getmac`` command is not available directly. In that case, start it with the Python interpreter. See :ref:`python-invoke` for details.

.. note::
   On Windows, ``getmac.exe`` is a *system binary* that is part of Windows. Windows can run it instead of the ``getmac`` command that ``pip`` installs. The order of the folders in the ``PATH`` environment variable controls which command runs. To prevent this problem, add the ``\Scripts\`` folder of your Python installation to the ``PATH`` variable of your user. Examples: ``C:\Users\<USERNAME>\AppData\Local\Programs\Python\Python39\Scripts``, ``C:\Users\<USERNAME>\scoop\apps\python\current\Scripts``.


.. code-block:: shell

   # Show the usage and the command-line arguments
   getmac --help

   # Show the current version
   getmac --version

   # With no arguments, show the MAC address of the default network interface
   getmac

   # Give an interface name, an IPv4 or IPv6 address, or a hostname
   getmac --interface ens33
   getmac --ip 192.168.0.1
   getmac --ip6 ::1
   getmac --hostname home.router


Examples
========

Remote hosts
------------

To get the MAC address of a remote host, the host must be in the ARP table. By default, getmac sends a UDP packet to a high port on the host to populate the table. The default port is ``55555``. To disable this, use ``--no-network-requests`` (or ``-N``):

.. code-block:: shell

   getmac --no-network-requests --ip 192.168.0.1
   getmac -N -n home.router

The system adds the host to the table only when the host replies. The reply can arrive after getmac checks the table. By default, getmac checks the table one time. To make getmac check the table again for a maximum number of seconds, use ``--arp-timeout``:

.. code-block:: shell

   getmac --ip 192.168.0.1 --arp-timeout 1

To change the UDP port, use ``--override-port``:

.. code-block:: shell

   getmac --ip 192.168.0.1 --override-port 9001


Advanced usage
==============

Control the method selection
----------------------------

getmac has many methods to get information on different platforms. The platform, and the commands and libraries that are available, set which methods getmac uses. This system is not perfect. Sometimes you must control the method selection yourself, for example to debug a problem.

To replace the platform that getmac detects, use ``--override-platform``. This is useful to debug problems. It is also useful when you know that a method for a different platform works on this platform. All values that ``platform.system()`` returns are valid.

.. code-block:: shell

   # Use "linux" as the detected platform, and use the "linux" methods
   getmac -i eth0 --override-platform linux

   # Use "windows" as the detected platform, and use the "windows" methods
   getmac --ip 192.168.0.1 --override-platform windows


To use one specific method, use ``--force-method``. getmac then uses that method, even if the method does not work on this system.

.. code-block:: shell

   getmac -v -dddd --ip 192.168.0.1 --force-method ctypeshost


Show log messages and debug output
----------------------------------

.. note::
   When you report an issue or ask for help, enable the log messages and the highest debug level: ``getmac -v -dddd [arguments]``

By default, getmac shows only the result. To show the log messages also, add the ``-v`` (``--verbose``) argument to the command. The messages help you debug problems and understand what getmac does.

.. code-block:: shell

   getmac --verbose
   getmac -v -i eth0
   getmac --verbose --ip 192.168.0.1


getmac also has a debug mode with 4 levels. The ``-d`` (``--debug``) argument enables debug level 1. Each additional ``d`` increases the level by 1. The debug output shows only if you also use ``-v`` (``--verbose``).

.. code-block:: shell

   # Debug level 1
   getmac -v -d

   # Debug level 1, with another argument
   getmac -v -d -i enp11s4

   # Debug level 2 (two 'd' characters)
   getmac -v -dd -n home.router

   # Debug level 3
   getmac -v -ddd --ip 192.168.0.1

   # Debug level 4
   getmac -v -dddd -i eth0



.. _python-invoke:

Start getmac with the Python interpreter
========================================

If the ``getmac`` command does not work, use ``python3 -m getmac``. Replace ``python3`` with the command that starts Python. Use the same Python installation that you installed getmac into.

On Windows, this command can be ``py``, for example ``py -m getmac``. It can also be ``python``, for example ``python -m getmac``.

In the examples on this page, replace ``getmac`` with ``python3 -m getmac``, or with the command for your platform.

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


These examples start getmac as a Python module, with the short forms of the arguments:

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
