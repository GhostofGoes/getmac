
[![Latest version on PyPI](https://badge.fury.io/py/get-mac.svg)](https://pypi.org/project/get-mac/)
[![Travis CI build status](https://travis-ci.org/GhostofGoes/get-mac.svg?branch=master)](https://travis-ci.org/GhostofGoes/get-mac)

Get the MAC address of remote hosts or network interfaces using Python.

It provides a platform-independant interface to get the MAC addresses of:

* System network interfaces (by interface name)
* Remote hosts on the local network (by IPv4/IPv6 address or hostname)

It provides one function: `get_mac_address()`

## Features
* Pure-Python
* Supports Python 2.6+, 3.2+, pypy, and pypy3
* No dependencies
* Small size
* Can be used as an independant .py file
* Simple terminal tool (when installed as a package)

# Usage

## Python examples
```python
from getmac import get_mac_address
eth_mac = get_mac_address(interface="eth0")
win_mac = get_mac_address(interface="Ethernet 3")
ip_mac = get_mac_address(ip="192.168.0.1")
ip6_mac = get_mac_address(ip6="::1")
host_mac = get_mac_address(hostname="localhost")
updated_mac = get_mac_address(ip="10.0.0.1", network_request=True)
```

## Terminal examples
```bash
get-mac --interface 'eth0'
get-mac --ip '192.168.0.1'
get-mac --ip6 '::1'
python -m getmac --interface 'eth0'
python -m getmac --ip '192.168.0.1'
python -m getmac --ip6 '::1'
```

Note: the terminal interface will not work on Python 2.6 (Sorry CentOS 6 users!).

## get_mac_address()
* `interface`: Name of a network interface on the system.
* `ip`: IPv4 address of a remote host.
* `ip6`: IPv6 address of a remote host.
* `hostname`: Hostname of a remote host.
* `network_request`: If an network request (ping usually) should be made to update and populate the
ARP table of remote hosts used to lookup MACs in most circumstances.
Disable this if you want to just use what's already in the table, or
if you have requirements to prevent network traffic.

## Notes
* If none of the arguments are selected, the default network interface for the system will be used.
* "Remote hosts" refer to hosts in your local layer 2 network, also
commonly referred to as a "broadcast domain", "LAN", or "VLAN". As far
as I know, there is not a reliable method to get a MAC address for a
remote host external to the LAN. If you know any methods otherwise, please
open a GitHub issue or shoot me an email, I'd love to be wrong about this.
* The first four arguments are mutually exclusive. `network_request` does not have any functionality
when the `interface` argument is specified, and can be safely set if using in a script.
* The physical transport is assumed to be Ethernet (802.3). Others, such as
Wi-Fi (802.11), are currently not tested or considored. I plan to
address this in the future, and am definitely open to pull requests
or issues related to this, including error reports.
* Exceptions will be handled silently and returned as a None.
    If you run into problems, you can set DEBUG to true and get more
    information about what's happening. If you're still having issues,
    please create an issue on GitHub and include the output with DEBUG enabled.
* Messages are output using the warnings library.
If you are using logging, they can be captured using logging.captureWarnings().
Otherwise, they can be suppressed using warnings.filterwarnings("ignore").
https://docs.python.org/3/library/warnings.html

# Platforms
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

# Caveats & Known issues

## Caveats
* Depending on the platform, there could be a performance detriment,
due to heavy usage of regular expressions.
* Testing is only on a few platforms (Ubuntu 14+, Windows 10, OSX), so your
mileage may vary. Please report any problems by opening a issue on GitHub!

## Known Issues
* Hostnames for IPv6 devices are not yet supported.
* The "default" of selecting the default route interface for the platform
currently attempts to use common default interfaces, not the actual default.

# Sources
Many of the methods used to acquire an address and the core logic framework
are attributed to the CPython project's UUID implementation.
* https://github.com/python/cpython/blob/master/Lib/uuid.py
* https://github.com/python/cpython/blob/2.7/Lib/uuid.py
* [_unix_fcntl_by_interface](https://stackoverflow.com/a/4789267/2214380)
* [_windows_get_remote_mac_ctypes](goo.gl/ymhZ9p)
* [String joining](https://stackoverflow.com/a/3258612/2214380)

# TODO
Full list of tasks and bugs can be found in TODO.md

# License
MIT. Feel free to copy, modify, and use to your heart's content. Have fun!
