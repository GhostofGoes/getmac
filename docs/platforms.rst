=========
Platforms
=========

This page lists the platforms that getmac supports, and the commands, libraries and files that getmac uses on each platform.

Supported platforms
===================

All or almost all features of getmac work on the supported platforms. Other versions of the same family or distribution can work, but I did not test them. They can have bugs or missing features.

- Windows

  - Desktop: 7, 8, 8.1, 10, 11. Thanks to @StevenLooman for the tests on Windows 11.
  - Server: 2025, 2022
  - Partial support, not tested: 2000, XP, Vista

- Linux distributions

  - CentOS and RHEL 6 and later
  - Ubuntu 16.04 and later. Ubuntu 15.10 and earlier should work, but I did not test them.
  - Fedora 24 and later

- macOS (Darwin): the latest release. I also tested macOS 13 and 14 successfully.
- Android 6 and later. See :ref:`platforms-android`.
- Windows Subsystem for Linux (WSL)
- FreeBSD 11 and later
- OpenBSD
- Docker. See :doc:`docker`.
- BusyBox. BusyBox is not a platform, but some of the methods work with it.

Commands and techniques by platform
===================================

- Windows

  - Commands: ``getmac.exe``, ``ipconfig.exe``, ``arp.exe``, ``netsh.exe``, ``wmic.exe``
  - Libraries: ``ctypes``, ``socket``
  - Default interface: ``netsh.exe``

- Linux and other Unix systems

  - Commands: ``arp``, ``ip``, ``ifconfig``, ``netstat``, ``ip link``, ``arping`` (the iputils variant and the Habets variant)
  - Libraries: ``fcntl``, ``socket``
  - Files: ``/sys/class/net/{iface}/address``, ``/proc/net/arp``
  - Default interface: ``/proc/net/route``, ``route``, ``ip route list``

- HP-UX

  - Commands: ``lanscan``

- macOS (Darwin)

  - Commands: ``networksetup``, ``arping``
  - Many of the same commands as Linux

- WSL

  - getmac uses Windows commands for remote hosts.
  - getmac uses Unix commands for interfaces.

- OpenBSD

  - Commands: ``ifconfig``, ``arp``
  - Default interface: ``route``

- FreeBSD

  - Commands: ``ifconfig``, ``arp``
  - Default interface: ``netstat``

- Android: the same commands and files as Linux, if they are available. See :ref:`platforms-android`.

The :doc:`api` lists each method, with the command or file that it uses.

.. _platforms-android:

Android
=======

Newer versions of Android do not have many of the commands that getmac uses. They also restrict access to network information. Thus, getmac may find nothing.

`BusyBox <https://busybox.net/>`__, or the ``iproute2`` and ``net-tools`` packages from `Termux <https://termux.dev/>`__, add the missing commands. Android's restrictions can still block these commands.

Python 3.13 and later on Android identify the platform as Linux. Thus, getmac uses the Linux methods.
