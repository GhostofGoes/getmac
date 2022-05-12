
[![Latest version on PyPI](https://badge.fury.io/py/getmac.svg)](https://pypi.org/project/getmac/)
[![Coverage Status](https://coveralls.io/repos/github/GhostofGoes/getmac/badge.svg?branch=master)](https://coveralls.io/github/GhostofGoes/getmac?branch=master)
[![Travis CI build status](https://travis-ci.org/GhostofGoes/getmac.svg?branch=master)](https://travis-ci.org/GhostofGoes/getmac)
[![Appveyor build status](https://ci.appveyor.com/api/projects/status/4o9mx4d35adrbssq/branch/master?svg=true)](https://ci.appveyor.com/project/GhostofGoes/get-mac)
[![PyPI download](https://pepy.tech/badge/getmac)](https://pepy.tech/project/getmac)
[![PyPI downloads of the old name](https://pepy.tech/badge/get-mac)](https://pepy.tech/project/get-mac)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/ambv/black)

Pure-Python package to get the MAC address of network interfaces and hosts on the local network.

It provides a platform-independent interface to get the MAC addresses of:

* System network interfaces (by interface name)
* Remote hosts on the local network (by IPv4/IPv6 address or hostname)

It provides one function: `get_mac_address()`

[![asciicast](https://asciinema.org/a/rk6dUACUcZY18taCuIBE5Ssus.png)](https://asciinema.org/a/rk6dUACUcZY18taCuIBE5Ssus)

[![asciicast](https://asciinema.org/a/n3insrxfyECch6wxtJEl3LHfv.png)](https://asciinema.org/a/n3insrxfyECch6wxtJEl3LHfv)


## Should you use this package?
If you only need the addresses of network interfaces, have a limited set
of platforms to support, and are able to handle C-extension modules, then
you should instead check out the excellent [netifaces](https://pypi.org/project/netifaces/)
package by Alastair Houghton. It is significantly faster, well-maintained,
and has been around much longer than this has. Another great option that
fits these requirements is the well-known and battle-hardened
[psutil](https://github.com/giampaolo/psutil) package by Giampaolo Rodola.

If the only system you need to run on is Linux, you can run as root,
and C-extensions modules are fine, then you should instead check out the
[arpreq](https://pypi.org/project/arpreq/) package by Sebastian Schrader.
It can be significantly faster, especially in the case of hosts that
don't exist (at least currently).

If you want to use `psutil`, `scapy`, or `netifaces`, I have examples of how to do
so in a [GitHub Gist](https://gist.github.com/GhostofGoes/0a8e82930e75afcefbd879a825ba4c26).

## Installation
Stable release from PyPI

```bash
pip install getmac
```

Latest development version

```bash
pip install https://github.com/ghostofgoes/getmac/archive/master.tar.gz
```

## Python examples
```python
from getmac import get_mac_address
eth_mac = get_mac_address(interface="eth0")
win_mac = get_mac_address(interface="Ethernet 3")
ip_mac = get_mac_address(ip="192.168.0.1")
ip6_mac = get_mac_address(ip6="::1")
host_mac = get_mac_address(hostname="localhost")
updated_mac = get_mac_address(ip="10.0.0.1", network_request=True)

# Changing the port used for updating ARP table (UDP packet)
from getmac import getmac
getmac.PORT = 44444  # Default: 55555
print(getmac.get_mac_address(ip="192.168.0.1", network_request=True))

# Enabling debugging
from getmac import getmac
getmac.DEBUG = 2  # DEBUG level 2
print(getmac.get_mac_address(interface="Ethernet 3"))
```

## Terminal examples
**Python 2 users**: use `getmac2` or `python -m getmac` instead of `getmac`.
```bash
getmac --help
getmac --version

# Invoking with no arguments will return MAC of the default interface
getmac

# Usage as a module
python3 -m getmac

# Interface names, IPv4/IPv6 addresses, or Hostnames can be specified
getmac --interface ens33
getmac --ip 192.168.0.1
getmac --ip6 ::1
getmac --hostname home.router

# Running as a Python module with shorthands for the arguments
python -m getmac -i 'Ethernet 4'
python -m getmac -4 192.168.0.1
python -m getmac -6 ::1
python -m getmac -n home.router

# Getting the MAC address of a remote host requires the ARP table to be populated.
# By default, getmac will populate the table by sending a UDP packet to a high port on the host (defaults to 55555).
# This can be disabled with --no-network-request, as shown here:
getmac --no-network-request -4 192.168.0.1
python -m getmac --no-network-request -n home.router

# Enable output messages
getmac --verbose

# Debug levels can be specified with '-d'
getmac -v --debug
python -m getmac -v -d -i enp11s4
python -m getmac -v -dd -n home.router
```

## Function: get_mac_address()
* `interface`: Name of a network interface on the system
* `ip`: IPv4 address of a remote host
* `ip6`: IPv6 address of a remote host
* `hostname`: Hostname of a remote host
* `network_request`: If an network request should be made to update
and populate the ARP/NDP table of remote hosts used to lookup MACs
in most circumstances. Disable this if you want to just use what's
already in the table, or if you have requirements to prevent network
traffic. The network request is a empty UDP packet sent to a high
port, 55555 by default. This can be changed by setting `getmac.PORT`
to the desired integer value. Additionally, on Windows, this will
send a UDP packet to 1.1.1.1:53 to attempt to determine the default interface.

## Configuration
* `logging.getLogger('getmac')`: Runtime messages and errors are recorded to the `getmac` logger using the `logging` 
module. They can be configured by using `logging.basicConfig()` or adding handlers to the `getmac` logger.
* `getmac.getmac.DEBUG`: integer value that controls debugging output. The higher the value, the more output you get.
* `getmac.getmac.PORT`: UDP port used to populate the ARP/NDP table 
(see the documentation of the `network_request` argument in `get_mac_address()` for details)

## Features
* Pure-Python (no compiled C-extensions required!)
* Python 2.7 and 3.4+
* Lightweight, with no dependencies and a small package size
* Can be dropped into a project as a standalone .py file
* Supports most interpreters: CPython, pypy, pypy3, IronPython 2.7, and Jython 2.7
* Provides a simple command line tool (when installed as a package)
* MIT licensed!

## Legacy Python versions
If you are running a old Python (2.6/3.3 and older) or interpreter, then you
can install an older version of `getmac` that supported that version.
 The wheels are available in the
 [GitHub releases](https://github.com/GhostofGoes/getmac/releases), or
 from PyPI with a current version of `pip` and some special arguments.
* Python 2.5: get-mac 0.5.0
* Python 2.6: getmac 0.6.0
* Python 3.2: get-mac 0.3.0
* Python 3.3: get-mac 0.3.0

NOTE: these versions do not have many of the performance improvements,
platform support, and bug fixes that came with later releases.
They generally work, just not as well. However, if you're using such
an old Python, you probably don't care about all that :)

## Notes
* If none of the arguments are selected, the default
network interface for the system will be used.
* "Remote hosts" refer to hosts in your local layer 2 network, also
commonly referred to as a "broadcast domain", "LAN", or "VLAN". As far
as I know, there is not a reliable method to get a MAC address for a
remote host external to the LAN. If you know any methods otherwise, please
open a GitHub issue or shoot me an email, I'd love to be wrong about this.
* The first four arguments are mutually exclusive. `network_request`
does not have any functionality when the `interface` argument is
specified, and can be safely set if using in a script.
* The physical transport is assumed to be Ethernet (802.3). Others, such as
Wi-Fi (802.11), are currently not tested or considered. I plan to
address this in the future, and am definitely open to pull requests
or issues related to this, including error reports.
* Exceptions will be handled silently and returned as a None.
    If you run into problems, you can set DEBUG to true and get more
    information about what's happening. If you're still having issues,
    please create an issue on GitHub and include the output with DEBUG enabled.

## Commands and techniques by platform
* Windows
    * Commands: `getmac.exe`, `ipconfig.exe`, `arp.exe`, `wmic.exe`
    * Libraries: `uuid`, `ctypes`, `socket`
* Linux/Unix
    * Commands: `arp`, `ip`, `ifconfig`, `netstat`, `ip link`, `lanscan`
    * Libraries: `uuid`, `fcntl`, `socket`
    * Files: `/sys/class/net/{iface}/address`, `/proc/net/arp`
    * Default interfaces: `/proc/net/route`, `route`, `ip route list`
* Mac OSX (Darwin)
    * `networksetup`
    * Same commands as Linux
* WSL
    * Windows commands are used for remote hosts
    * Unix commands are used for interfaces
* OpenBSD
    * Commands: `ifconfig`, `arp`
    * Default interfaces: `route`
* FreeBSD
    * Commands: `ifconfig`, `arp`
    * Default interfaces: `netstat`

## Platforms currently supported
All or almost all features should work on "supported" platforms. 
While other versions of the same family or distro may work, they
are untested and may have bugs or missing features.
* Windows
    * Desktop: 7, 8, 8.1, 10, 11 (thanks @StevenLooman for testing Windows 11!)
    * Server: TBD
    * Partially supported (untested): 2000, XP, Vista
* Linux distros
    * CentOS/RHEL 6+ (Only with Python 2.7+)
    * Ubuntu 16.04+ (15.10 and older should work, but are untested)
    * Fedora (24+)
* Mac OSX (Darwin)
    * The latest two versions probably (TBD)
* Windows Subsystem for Linux (WSL)
* FreeBSD (11+)
* OpenBSD
* Docker

## Docker
Add `-v /proc/1/net/arp:/host/arp -e ARP_PATH=/host/arp` to access arp table of host inside container in bridge network mode.
```bash
docker build -f packaging/Dockerfile -t getmac .
docker run -it getmac:latest --help
docker run -it getmac:latest --version
docker run -it getmac:latest -n localhost
docker run --rm -it -v /proc/1/net/arp:/host/arp -e ARP_PATH=/host/arp getmac:latest -n 192.168.0.1
```

## Caveats
* Depending on the platform, there could be a performance detriment,
due to heavy usage of regular expressions.
* Platform test coverage is imperfect. If you're having issues,
then you might be using a platform I haven't been able to test.
Keep calm, open a GitHub issue, and I'd be more than happy to help.

## Known Issues
* Linux, WSL: Getting the mac of a local interface IP does not currently work
(`getmac -4 10.0.0.4` will fail if `10.0.0.4` is the IP address of a local interface).
This issue may be present on other POSIX systems as well.
* Hostnames for IPv6 devices are not yet supported.
* Windows: the "default" (used when no arguments set or specified) 
of selecting the default route interface only works effectively 
if `network_request` is enabled. If not, `Ethernet` is used as the default.
* IPv6 support is good but lags behind IPv4 in some places
and isn't as well-tested across the supported platform set.

## Background and history
The Python standard library has a robust set of networking functionality,
such as `urllib`, `ipaddress`, `ftplib`, `telnetlib`, `ssl`, and more.
Imagine my surprise, then, when I discovered there was not a way to get a
seemingly simple piece of information: a MAC address. This package was born
out of a need to get the MAC address of hosts on the network without
needing admin permissions, and a cross-platform way get the addresses
of local interfaces.

In Fall 2018 the package name changed to `getmac` from `get-mac`. This
affected the package name, the CLI script, and some of the documentation.
There were no changes to the core library code. While both package names 
will updated on PyPI, the use of `getmac` is preferred.

## Contributing
Contributors are more than welcome!
See the [contribution guide](CONTRIBUTING.md) to get started,
and checkout the [todo list](TODO.md) for a full list of tasks and bugs.

Before submitting a PR, please make sure you've completed the
[pull request checklist](CONTRIBUTING.md#Code_requirements)!

The [Python Discord server](https://discord.gg/python) is a good place
to ask questions or discuss the project (Handle: @KnownError).

### Contributors
* Christopher Goes (@ghostofgoes) - Author and maintainer
* Calvin Tran (@cyberhobbes) - Windows interface detection improvements
* Daniel Flanagan (@FlantasticDan) - Code cleanup
* @emadmahdi - Android fixes
* Izra Faturrahman (@Frizz925) - Unit tests using the platform samples
* Jose Gonzalez (@Komish) - Docker container and Docker testing
* @fortunate-man - Awesome usage videos
* @martmists - legacy Python compatibility improvements
* @hargoniX - scripts and specfiles for RPM packaging
* Ville Skyttä (@scop) - arping lookup support
* Tomasz Duda (@tomaszduda23) - support for docker in network bridge mode
* Steven Looman (@StevenLooman) - Windows 11 testing

## Sources
Many of the methods used to acquire an address and the core logic framework
are attributed to the CPython project's UUID implementation.
* https://github.com/python/cpython/blob/master/Lib/uuid.py
* https://github.com/python/cpython/blob/2.7/Lib/uuid.py

### Other notable sources
* [_unix_fcntl_by_interface](https://stackoverflow.com/a/4789267/2214380)
* [_windows_get_remote_mac_ctypes](goo.gl/ymhZ9p)
* [String joining](https://stackoverflow.com/a/3258612/2214380)

## License
MIT. Feel free to copy, modify, and use to your heart's content. Enjoy :)
