==================================
Collecting command output samples
==================================

getmac's tests don't run real commands. They run the parsers against real output saved in ``tests/samples/``, so a fix for one platform can be tested on every other. That makes samples the most useful thing you can send me, even if you don't write any code: a captured ``arp -a`` from a platform I don't have is often all it takes to add support for it. This page covers how to capture them, what to name them, and what to clean up before you commit or attach them to an issue.

If you're adding a method, this is the first step of :doc:`adding_methods`.


Using collect_samples.py
========================

Running the script
------------------

``scripts/collect_samples.py`` runs the commands (and reads the files) that getmac uses on the current platform, and saves the output of each one to its own file in ``tests/samples/<platform>_<version>/`` (e.g. ``tests/samples/ubuntu_24.04/``). It only needs Python 3.9 or newer and doesn't import getmac, so you can copy the single file to any machine and run it there. Outside a getmac checkout it saves to ``./samples/<platform>_<version>/`` instead, or to the directory given with ``--output-root``.

.. code-block:: shell

   python scripts/collect_samples.py --dry-run  # list what would be collected
   python scripts/collect_samples.py  # run the collection

Commands that aren't installed are skipped. Exit codes and error messages for everything it ran are logged to ``collect_samples.log`` in the same directory. A few commands, such as ``arping``, only work as root (or Administrator on Windows), so run it again with ``sudo`` if you want those too. By default, it looks up every interface it finds, and the default gateway as the :term:`remote host`. The options below change that.

Options
-------

``--dry-run``
   List what would be collected, without saving anything. A few read-only commands (e.g. ``ip route list 0/0``) may still be run to find the interfaces and the gateway.
``-f``, ``--force``
   Overwrite samples that already exist.
``-t``, ``--timeout``
   How long to wait for each command, in seconds (default 15).
``-n``, ``--name``
   Name of the samples directory, instead of the detected platform and version.
``-p``, ``--platform``
   Collect the commands for this platform instead of the detected one. Use ``other`` to collect the commands getmac falls back to on a platform it doesn't know.
``-i``, ``--interface``
   An interface to run the interface commands for. Can be repeated. ``--default-interface-only`` runs them for just the :term:`default interface`.
``--ip``
   The IP of a remote host to look up. Can be repeated.
``--no-network``
   Skip commands that send packets on the network (``arping``).
``-o``, ``--output-root``
   The directory to create the samples directory in.

``python scripts/collect_samples.py --help`` has the exact list.

Adding a new command to the script
----------------------------------

The script only knows about commands getmac already uses. If you're adding a method for a *new* command, add it to the script too, or the new command's output won't be collected for anyone else. The commands are in ``GROUPS`` in ``scripts/collect_samples.py``, grouped by platform. Add one entry per command (``check_command`` call) to the group for the platform it's for, using the ``{iface}`` and ``{ip}`` placeholders for the interface and host, or ``File("/path/{iface}")`` for a file:

.. code-block:: python

   "linux": (
       ...
       cmd("ip addr"),
       cmd("ip addr show {iface}"),  # new
       ...
   ),

``tests/test_collect_samples.py`` fails if a method uses a command that ``GROUPS`` doesn't include for that method's platforms, so you'll find out if you forget.


Collecting by hand
==================

You can also run a command yourself and save the output with ``tee``:

.. code-block:: shell

   mkdir -p tests/samples/ubuntu_24.04
   ip addr show ens33 | tee tests/samples/ubuntu_24.04/ip_addr_show_ens33.out

Also capture what the command does for something that doesn't exist, along with the exit code (``echo $?`` when running it by hand). For example, ``ip addr show eth9`` prints ``Device "eth9" does not exist.`` and exits with code 1. The script logs this to ``collect_samples.log`` for you.


Naming files
============

Files are named after the command line, with a ``.out`` extension. The script follows these rules, and so should you if you do it by hand:

- Spaces become underscores: ``arp -a`` is ``arp_-a.out``.
- Dots and colons in IP addresses become dashes: ``arp 10.0.2.2`` is ``arp_10-0-2-2.out``.
- A ``/`` becomes ``slash``: ``ip route list 0/0`` is ``ip_route_list_0slash0.out``.
- On Windows, a ``/all`` option becomes ``-all``, and ``.exe`` is dropped: ``ipconfig.exe /all`` is ``ipconfig_-all.out``.
- The contents of a file are named ``cat_`` plus its path with dashes: ``/proc/net/arp`` is ``cat_proc-net-arp.out``.

If you're not sure, run the script with ``--dry-run`` to see the exact names it would use.


Cleaning up samples
===================

The samples contain real :term:`MAC addresses <MAC address>`, IP addresses, and hostnames from your system, so review and redact them before you commit or share them. Keep the output format intact. Locally administered MACs (``02:00:00:00:00:01``) and `documentation IP ranges <https://www.rfc-editor.org/info/rfc5737/>`__ (``192.0.2.0/24``) make good replacements.


Where samples go
================

- Samples go in a directory named for the OS and version, such as ``ubuntu_18.04``, ``macos_10.12.6`` or ``windows_10``.
- Windows samples must go in a directory whose name starts with ``windows``, so ``.gitattributes`` can preserve their Windows line endings (CRLF).
- Output taken from other projects goes in ``tests/samples/third_party/<project>/``, along with that project's license and a short README saying where it came from. The project gets credited in the main README.

Once you have samples, go on to :doc:`adding_methods` to write the method and its tests.
