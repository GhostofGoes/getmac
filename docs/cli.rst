
Basic Usage
===========

The ``getmac`` command is included when you install the package. This provides developers and power users (like you!) a cross-platform tool to get MAC addresses.

.. note::
   Depending on your Python environment, you may be able to invoke it directly (``getmac``) or have to reference your Python interpreter to invoke it. See :ref:`python-invoke` for details.

.. note::
   On Windows, ``getmac.exe`` is a system binary. Depending on the value of the ``PATH`` environment variable, it may get prioritized over the ``getmac`` shim installed by pip. Ensure the ``\Scripts\`` folder in site-packages is added to the PATH variable for your user!


.. code-block:: shell

   # Print usage and command line arguments
   getmac --help

   # Print the current version
   getmac --version

   # Invoking with no arguments will return MAC address of the default network interface
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




.. ref: python-invoke

Usage by specifying Python interpreter
--------------------------------------

If ``getmac`` doesn't work, try ``python3 -m getmac``, where ``python3`` is whatever command you use to run Python and used to install the package.

On Windows, this may be ``py``, e.g. ``py -m getmac``, or just ``python``, e.g. ``python -m getmac``.

When invoking in this fashion, in the examples above you can simply replace calls to ``getmac`` with ``python3 -m getmac`` (or whatever invocation applies to your platform).

.. code-block:: shell

   python3 -m getmac
   python3 -m getmac --help
   python3 -m getmac --version


Examples of running as a Python module with shorthands for the arguments

.. code-block:: shell

   python3 -m getmac -i 'Ethernet 4'
   python3 -m getmac -4 192.168.0.1
   python3 -m getmac -6 ::1
   python3 -m getmac -n home.router


Arguments
=========

    Put requisite calls to sphinx_argparse_cli here.===
