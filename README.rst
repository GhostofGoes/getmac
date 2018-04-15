.. image:: https://badge.fury.io/py/get-mac.svg
    :target: https://badge.fury.io/py/get-mac
    :alt: PyPI
.. image:: https://travis-ci.org/GhostofGoes/get-mac.svg?branch=master
    :target: https://travis-ci.org/GhostofGoes/get-mac
    :alt: Build Status


Get the MAC address of remote hosts or network interfaces using Python.

It provides a platform-independant interface to get the MAC addresses of:

* System network interfaces (by interface name)
* Remote hosts (by IPv4/IPv6 address or hostname)

It provides one function: get_mac_address()


Features
========

* Pure-Python
* Supports Python 2.6+, 3.2+, pypy, and pypy3
* No dependencies
* Small size
* Can be used as an independant .py file
* Simple terminal tool (when installed as a package)


Usage
=====

In Python
---------
.. code-block:: python

   from getmac import get_mac_address
   eth_mac = get_mac_address(interface="eth0")
   win_mac = get_mac_address(interface="Ethernet 3")
   ip_mac = get_mac_address(ip="192.168.0.1")
   host_mac = get_mac_address(hostname="localhost")
   updated_mac = get_mac_address(ip="10.0.0.1", network_request=True)

Terminal
--------
.. code-block:: bash

   get-mac --interface 'eth0'
   get-mac --ip '192.168.0.1'
   python -m getmac --interface 'eth0'
   python -m getmac --ip '192.168.0.1'


get_mac_address()
=================

* `interface`: Name of a network interface on the system.
* `ip`: IPv4 address of a remote host.
* `ip6`: IPv6 address of a remote host.
* `hostname`: Hostname of a remote host.
* `network_request`: If an network request (ping usually) should be made to update and populate the
ARP table of remote hosts used to lookup MACs in most circumstances. Disable this if you want to
just use what's already in the table, or if you have requirements to prevent network traffic.

Notes
----
* The first four arguments are mutually exclusive. `network_request` does not have any functionality
when the `interface` argument is specified, and can be safely set if using in a script.
* If none of the arguments are selected, the default network interface for the system will be used.
* For the time being, it assumes you are using Ethernet.
* Exceptions will be handled silently and returned as a None.
    If you run into problems, create an issue on GitHub,
    or set DEBUG to true if you're brave.
* Messages are output using the warnings library.
If you are using logging, they can be captured using logging.captureWarnings().
Otherwise, they can be suppressed using warnings.filterwarnings("ignore").
https://docs.python.org/3/library/warnings.html



Platforms
=========

* Windows
    * Versions: 2000, XP, Vista, 7, 8/8.1, 10
    * Commands: `ipconfig`, `ping`
    * Libraries: `ctypes`
* Linux
    * Distros: Debian, RHEL
    * Commands: `arp`, `ip`, `ifconfig`
    * Libraries: `fcntl`
* Mac OS X (Darwin)
    * Same linux/unix
* HP-UX:
    * `lanscan`
* Generic Unix-based
    * Commands: `netstat`, `cat`


Caveats & Known issues
======================

Caveats
-------
* Depending on the platform, there could be a performance detriment, due to heavy usage of
regular expressions.
* Testing is only on a few platforms (Ubuntu 14+, Windows 10, OSX), so your mileage may vary.
Please report any problems by opening a issue on GitHub!

Known Issues
------------
* Hostnames for IPv6 devices are not yet supported.
* The "default" of selecting the default route interface for the platform
currently attempts to use common default interfaces, not the actual default.

Sources
=======
Many of the methods used to acquire an address and the core logic framework
are attributed to the CPython project's UUID implementation.
    * https://github.com/python/cpython/blob/master/Lib/uuid.py
    * https://github.com/python/cpython/blob/2.7/Lib/uuid.py

Other sources are noted with inline comments at the appropriate sections.



TODO
====

* Cache results on regex-heavy functions (add a arg to disable this behavior)
* Decide on what the error behavior should be. Is returning None for both
errors and simple failures to find acceptable?
* New platforms
    * Android
    * FreeBSD
    * OpenBSD
    * Solaris
    * Windows pre-2000


License
=======
MIT. Feel free to copy, modify, and use to your heart's content. Have fun!
