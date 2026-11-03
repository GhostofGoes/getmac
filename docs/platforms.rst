=========
Platforms
=========

This page covers which platforms getmac supports, and which methods (commands, files, and libraries) it uses to get MAC addresses on each of them.

Supported platforms
===================

All or almost all features should work on "supported" platforms. While other versions of the same family or distro may work, they are untested and may have bugs or missing features.

- Windows

  - Desktop: 7, 8, 8.1, 10, 11 (thanks @StevenLooman for testing Windows 11!)
  - Server: 2025, 2022
  - Partially supported (untested): 2000, XP, Vista

- Linux distros

  - CentOS/RHEL 6+
  - Ubuntu 16.04+ (15.10 and older should work, but are untested)
  - Fedora (24+)

- macOS (Darwin): the latest release, though macOS 14 and 13 have been tested with success.
- Android (6+), with limitations. See :ref:`platforms-android`.
- Windows Subsystem for Linux (WSL), both WSL1 and WSL2
- FreeBSD (11+)
- OpenBSD
- NetBSD (9.3+)
- DragonFly BSD (6.4+)
- Oracle Solaris 11.4
- illumos distros: OmniOS (r151054+), OpenIndiana (2026.04+). Others like SmartOS should work, but are untested.
- Docker. See :doc:`docker`.
- BusyBox (not technically a platform, but several of the methods work on this platform)

Linux, Windows, and macOS are tested in CI on every change, and so are NetBSD, DragonFly BSD, Solaris, and illumos (in VMs). FreeBSD and OpenBSD are tested by hand, so help testing them is always welcome. HP-UX has an interface method (``lanscan``), but I don't have a way to test it.

.. _platforms-methods:

Methods by platform
===================

getmac has a list of *methods*, each of which uses one command, file, or library to get a MAC. On each platform, getmac tries the methods for that platform in order, and uses the first one that works (:doc:`module_api` explains the details). The lists below are in the order the methods are tried in. Every method is documented in the :doc:`api`, including what it parses and any quirks.

To see which methods were chosen on your system, run ``getmac -v -dd``.

Windows
-------

Interfaces
   :class:`~getmac.getmac.GetmacExe` (``getmac.exe``), :class:`~getmac.getmac.IpconfigExe` (``ipconfig.exe /all``), :class:`~getmac.getmac.WmicExe` (``wmic.exe``)
IPv4 hosts
   :class:`~getmac.getmac.CtypesHost` (``SendARP`` from ``Iphlpapi``, via :mod:`ctypes`, sends an ARP request), :class:`~getmac.getmac.ArpExe` (``arp.exe -a``), :class:`~getmac.getmac.NetshNeighbors` (``netsh.exe int ipv4 show neigh``)
IPv6 hosts
   :class:`~getmac.getmac.NetshNeighbors` (``netsh.exe int ipv6 show neigh``)
Default interface
   :class:`~getmac.getmac.DefaultIfaceNetsh` (``netsh.exe int ipv4 show route``). With network requests enabled, ``get_mac_address()`` with no arguments first finds the IP of the default interface by connecting a UDP socket to ``1.1.1.1:53`` (Cloudflare's DNS server), and looks that IP up as a host. ``netsh.exe`` is only used if that doesn't find a MAC.

Linux
-----

Also used on Android and WSL2 (see below).

Interfaces
   :class:`~getmac.getmac.SysIfaceFile` (``/sys/class/net/<iface>/address``), :class:`~getmac.getmac.FcntlIface` (:func:`fcntl.ioctl`), :class:`~getmac.getmac.IfconfigWithIfaceArg` (``ifconfig <iface>``), :class:`~getmac.getmac.IfconfigOther` (``ifconfig -a``, ``-v``, or ``-av``), :class:`~getmac.getmac.IpLinkIface` (``ip link``), :class:`~getmac.getmac.NetstatIface` (``netstat -iae``)
IPv4 hosts
   :class:`~getmac.getmac.ArpFile` (``/proc/net/arp``), :class:`~getmac.getmac.ArpingHost` (``arping``, sends an ARP request), :class:`~getmac.getmac.IpNeighborShow` (``ip neighbor show``), :class:`~getmac.getmac.ArpVariousArgs` (``arp``)
IPv6 hosts
   :class:`~getmac.getmac.IpNeighborShow` (``ip neighbor show``), :class:`~getmac.getmac.ArpVariousArgs` (``arp``)
Default interface
   :class:`~getmac.getmac.DefaultIfaceLinuxRouteFile` (``/proc/net/route``), :class:`~getmac.getmac.DefaultIfaceIpRoute` (``ip route list 0/0``), :class:`~getmac.getmac.DefaultIfaceRouteCommand` (``route -n``)

``arping`` is the iputils, Habets, or BusyBox variant, and usually needs root.

WSL
---

WSL2 is a Linux VM with its own network, so it's detected as Linux and uses the Linux methods. WSL1 (platform ``wsl``) shares the Windows network, so it uses Linux methods for interfaces and Windows commands for hosts.

Interfaces
   :class:`~getmac.getmac.SysIfaceFile`, :class:`~getmac.getmac.FcntlIface`, :class:`~getmac.getmac.IfconfigWithIfaceArg`, :class:`~getmac.getmac.IpLinkIface`, :class:`~getmac.getmac.NetstatIface`
IPv4 hosts
   :class:`~getmac.getmac.ArpExe` (``arp.exe -a``)
IPv6 hosts
   No WSL1-specific methods yet, so the generic methods are tried (see :ref:`platforms-other`).
Default interface
   :class:`~getmac.getmac.DefaultIfaceLinuxRouteFile`, :class:`~getmac.getmac.DefaultIfaceIpRoute`, :class:`~getmac.getmac.DefaultIfaceRouteCommand`

macOS (Darwin)
--------------

Interfaces
   :class:`~getmac.getmac.DarwinNetworksetupIface` (``networksetup -getmacaddress <iface>``), :class:`~getmac.getmac.IfconfigEther` (``ifconfig``)
IPv4 hosts
   :class:`~getmac.getmac.ArpingHost` (``arping``, if it's installed, sends an ARP request), :class:`~getmac.getmac.ArpVariousArgs` (``arp``)
IPv6 hosts
   :class:`~getmac.getmac.NdpNeighbors` (``ndp -an``), :class:`~getmac.getmac.ArpVariousArgs` (``arp``)
Default interface
   :class:`~getmac.getmac.DefaultIfaceRouteGetCommand` (``route -n get default``)

FreeBSD
-------

Interfaces
   :class:`~getmac.getmac.IfconfigWithIfaceArg` (``ifconfig <iface>``)
IPv4 hosts
   :class:`~getmac.getmac.ArpFreebsd` (``arp <ip>``), :class:`~getmac.getmac.ArpVariousArgs` (``arp``)
IPv6 hosts
   :class:`~getmac.getmac.NdpNeighbors` (``ndp -an``), :class:`~getmac.getmac.ArpFreebsd`, :class:`~getmac.getmac.ArpVariousArgs`
Default interface
   :class:`~getmac.getmac.DefaultIfaceRouteGetCommand` (``route -n get default``), :class:`~getmac.getmac.DefaultIfaceFreeBsd` (``netstat -rn``)

OpenBSD
-------

Interfaces
   :class:`~getmac.getmac.IfconfigWithIfaceArg` (``ifconfig <iface>``)
IPv4 hosts
   :class:`~getmac.getmac.ArpOpenbsd` (``arp -an``)
IPv6 hosts
   :class:`~getmac.getmac.NdpNeighbors` (``ndp -an``), :class:`~getmac.getmac.ArpOpenbsd`
Default interface
   :class:`~getmac.getmac.DefaultIfaceOpenBsd` (``route -nq show -inet -gateway -priority 1``)

NetBSD and DragonFly BSD
------------------------

Interfaces
   :class:`~getmac.getmac.IfconfigWithIfaceArg` (``ifconfig <iface>``)
IPv4 hosts
   :class:`~getmac.getmac.ArpFreebsd` (``arp <ip>``)
IPv6 hosts
   :class:`~getmac.getmac.NdpNeighbors` (``ndp -an``), :class:`~getmac.getmac.ArpFreebsd`
Default interface
   :class:`~getmac.getmac.DefaultIfaceRouteGetCommand` (``route -n get default``)

Solaris and illumos
-------------------

Platform ``sunos`` covers Oracle Solaris and the illumos distros (OmniOS, OpenIndiana, SmartOS). All of these methods work for regular users, not just root.

Interfaces
   :class:`~getmac.getmac.DladmIface` (``dladm show-link``, then ``show-phys -m``, ``show-vnic``, or ``show-aggr -x`` depending on the type of link), :class:`~getmac.getmac.IfconfigWithIfaceArg` (``ifconfig <iface>``, which only shows the MAC to root)
IPv4 hosts
   :class:`~getmac.getmac.NetstatNetToMedia` (``netstat -pn -f inet``), :class:`~getmac.getmac.ArpVariousArgs` (``arp``)
IPv6 hosts
   :class:`~getmac.getmac.NetstatNetToMedia` (``netstat -pn -f inet6``), :class:`~getmac.getmac.ArpVariousArgs` (``arp``)
Default interface
   :class:`~getmac.getmac.DefaultIfaceRouteGetCommand` (``route -n get default``)

HP-UX
-----

Interfaces
   :class:`~getmac.getmac.LanscanIface` (``lanscan -ai``)
Hosts and default interface
   No HP-UX-specific methods yet, so the generic methods are tried (see :ref:`platforms-other`).

.. _platforms-other:

Other platforms
---------------

On a platform getmac doesn't know, or for a type of lookup that has no methods for the platform, getmac falls back to generic methods that work on many Unix-like systems:

Interfaces
   :class:`~getmac.getmac.IfconfigWithIfaceArg` (``ifconfig <iface>``), :class:`~getmac.getmac.IfconfigOther` (``ifconfig``), :class:`~getmac.getmac.IpLinkIface` (``ip link``), :class:`~getmac.getmac.NetstatIface` (``netstat -iae``)
Hosts
   :class:`~getmac.getmac.IpNeighborShow` (``ip neighbor show``), :class:`~getmac.getmac.ArpVariousArgs` (``arp``)
Default interface
   :class:`~getmac.getmac.DefaultIfaceIpRoute` (``ip route list 0/0``), :class:`~getmac.getmac.DefaultIfaceRouteCommand` (``route -n``), :class:`~getmac.getmac.DefaultIfaceRouteGetCommand` (``route -n get default``)

If you're on a platform that isn't listed here and these work for you, or don't, please open an issue! Adding proper support is usually straightforward, see :doc:`adding_methods`.

.. _platforms-android:

Android
=======

Android uses the Linux methods. Newer versions of Android don't have many of the commands getmac uses, and restrict access to network information, so getmac may not find anything. Installing `BusyBox <https://busybox.net/>`__ or the `Termux <https://termux.dev/>`__ ``iproute2`` and ``net-tools`` packages adds the missing commands, but they can still be blocked by Android's restrictions. The normal Linux methods should work fine, provided you have the proper permissions (usually, ``root``).

Python 3.13 and newer identify Android as its own platform (``platform.system()`` returns ``"Android"``). getmac treats it as Linux either way.

.. _platforms-known-issues:

Known issues
============

- Linux, WSL: Getting the MAC of a local interface IP does not currently work (``getmac --ip 10.0.0.4`` will fail if ``10.0.0.4`` is the IP address of a local interface). This issue may be present on other POSIX systems as well. Use the interface name instead.
- WSL1: remote IPv6 hosts aren't supported yet.
- Windows: ``ipconfig.exe`` (a fallback for when ``getmac.exe`` doesn't work) only finds interfaces by name in English output, since the adapter headers are translated. Adapter descriptions and MACs are found in any language.
- Windows: ``wmic.exe`` is deprecated as of Windows 10 21H1 and is being removed from Windows 11, so :class:`~getmac.getmac.WmicExe` may not work there. It's the last fallback for interfaces, so this only matters if ``getmac.exe`` and ``ipconfig.exe`` both fail.
- Android: see above.
- Hostnames for IPv6 devices are not yet supported.
- IPv6 support is good but lags behind IPv4 in some places and isn't as well-tested across the supported platform set.
