---
layout: default
---

# What is getmac?

getmac provides a cross-platform Pythonic interface to get MAC addresses
of remote hosts in a local network or system network interfaces. It has
no dependencies, supports all currently used versions of Python
(2.6+/3.4+) and interpreters (CPython, PyPy, IronPython, Jython).
It can be used as a package or dropped into your project as a
standalone .py file. The package from PyPI also has a simple command
line tool for conviencence working across multiple platforms.

You can get the MAC address of:
* Local system network interfaces (by interface name)
* Remote hosts on the local network (by IPv4/IPv6 address or hostname)

Installation: `python -m pip install --user getmac`

## Python usage
```python
from getmac import get_mac_address
eth_mac = get_mac_address(interface="eth0")
win_mac = get_mac_address(interface="Ethernet 3")
ip_mac = get_mac_address(ip="192.168.0.1")
ip6_mac = get_mac_address(ip6="::1")
host_mac = get_mac_address(hostname="localhost")
updated_mac = get_mac_address(ip="10.0.0.1", network_request=True)
```

## Terminal usage
```bash
getmac --help
getmac --version

# No arguments will return MAC of the default interface.
getmac
python -m getmac

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

# Getting the MAC address of a remote host obviously requires
# the ARP table to be populated. By default, getmac will do
# this for you by sending a small UDP packet to a high port (55555)
# If you don't want this to happen, you can disable it.
# This is useful if you're 100% certain the ARP table will be
# populated already, or in red team/forensic scenarios.
getmac --no-network-request -4 192.168.0.1
python -m getmac --no-network-request -n home.router

# Debug levels can be specified with '-d'
getmac --debug
python -m getmac -d -i enp11s4
python -m getmac -dd -n home.router
```

## get_mac_address()
* `interface`: Name of a network interface on the system.
* `ip`: IPv4 address of a remote host.
* `ip6`: IPv6 address of a remote host.
* `hostname`: Hostname of a remote host.
* `network_request`: If an network request should be made to update
and populate the ARP/NDP table of remote hosts used to lookup MACs
in most circumstances. Disable this if you want to just use what's
already in the table, or if you have requirements to prevent network
traffic. The network request is a empty UDP packet sent to a high
port, 55555 by default. This can be changed by setting `getmac.PORT`
to the desired integer value.

## Notes
* If no arguments are specified, it will return the MAC of the default network interface
* "Remote hosts" refer to hosts in the local layer 2 network, also referred to as a "broadcast domain", "LAN", or "VLAN"
* The first four arguments to `get_mac_address()` are mutually exclusive
* The physical transport is assumed to be Ethernet (802.3)
* Exceptions will be handled silently and returned as a None
* Messages are output using the `warnings` module, and `print()` if `getmac.DEBUG` enabled

## Caveats
* Depending on the platform, there could be a minor performance detriment due to heavy use of regular expressions
* Platform test coverage is imperfect. If you're having issues, please open an issue on GitHub

## Known Issues
* Hostnames for IPv6 devices are not yet supported.
* Windows: the "default" of selecting the default route interface for
the platform currently attempts to use `Ethernet` as the default,
not the actual default.

## License
MIT. Feel free to copy, modify, and use to your heart's content. Have fun!
