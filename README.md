
[![PyPI - Current Version](https://img.shields.io/pypi/v/getmac?label=PyPI)](https://pypi.org/project/getmac/)
[![codecov](https://codecov.io/github/GhostofGoes/getmac/branch/main/graph/badge.svg?token=5NxlAE9eGY)](https://codecov.io/github/GhostofGoes/getmac)
[![GitHub Actions Pipeline Status](https://github.com/ghostofgoes/getmac/actions/workflows/ci.yml/badge.svg)](https://github.com/GhostofGoes/getmac/actions)
![Python Version](https://img.shields.io/badge/Python-3.9|3.10|3.11|3.12|3.13|3.14-blue.svg)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/9388/badge)](https://www.bestpractices.dev/projects/9388)
[![Weekly PyPI downloads](https://pepy.tech/badge/getmac/week)](https://pepy.tech/project/getmac)
[![PyPI downloads](https://pepy.tech/badge/getmac)](https://pepy.tech/project/getmac)
[![PDM-managed](https://img.shields.io/endpoint?url=https%3A%2F%2Fcdn.jsdelivr.net%2Fgh%2Fpdm-project%2F.github%2Fbadge.json)](https://pdm-project.org)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

getmac is a pure-Python package. It gets the MAC addresses of network interfaces and of hosts on the local network.

getmac uses the same interface on all supported platforms to get the MAC addresses of:

- Network interfaces on this system, by interface name
- Remote hosts on the local network, by IPv4 address, IPv6 address, or hostname

Its primary function is `get_mac_address()`.

The full documentation is at https://ghostofgoes.github.io/getmac/.

[![asciicast](https://asciinema.org/a/n3insrxfyECch6wxtJEl3LHfv.png)](https://asciinema.org/a/n3insrxfyECch6wxtJEl3LHfv)


## Should you use this package?
Other packages can be a better choice in some conditions.

If all these conditions apply, look at the [netifaces](https://pypi.org/project/netifaces/) package by Alastair Houghton ([@al45tair](https://github.com/al45tair)):

- You need only the addresses of network interfaces.
- You support a limited set of platforms.
- You can use C-extension modules.

netifaces is much faster, because it is C code. Many projects used it for a long time. But nobody maintains it since [May 2021](https://github.com/al45tair/netifaces/commit/ec55b59e27542776f55e0f9e3213a75bf8e0f367), so it may not be a good choice for new projects. The [psutil](https://github.com/giampaolo/psutil) package by Giampaolo Rodola also agrees with these conditions. It is well known and widely used.

If all these conditions apply, look at the [arpreq](https://pypi.org/project/arpreq/) package by Sebastian Schrader:

- Your code runs only on Linux.
- You can run as root.
- You can use C-extension modules.

In some cases, arpreq is much faster.

To use `psutil`, `scapy`, or `netifaces`, see the examples in this [GitHub Gist](https://gist.github.com/GhostofGoes/0a8e82930e75afcefbd879a825ba4c26).

## Installation

### Stable release from PyPI

```bash
pip install getmac
```

### Latest development version

```bash
pip install https://github.com/ghostofgoes/getmac/archive/main.tar.gz
```

### Debian-based distributions
Some Linux distributions have a getmac package in `apt`. The packaging status below shows which distributions have it.

```bash
sudo apt install getmac
```

### OS Packaging Status

[![Packaging status](https://repology.org/badge/vertical-allrepos/getmac.svg)](https://repology.org/project/getmac/versions)

## Python examples
```python
from getmac import get_mac_address, settings

eth_mac = get_mac_address(interface="eth0")
win_mac = get_mac_address(interface="Ethernet 3")
ip_mac = get_mac_address(ip="192.168.0.1")
ip6_mac = get_mac_address(ip6="::1")
host_mac = get_mac_address(hostname="localhost")
updated_mac = get_mac_address(ip="10.0.0.1", network_request=True)

# Enable debugging
settings.DEBUG = 2  # DEBUG level 2
print(get_mac_address(interface="Ethernet 3"))

# Change the UDP port that getmac sends the packet to (the default port is 55555)
settings.PORT = 44444
print(get_mac_address(ip="192.168.0.1", network_request=True))

# After getmac sends the UDP packet, check the ARP table again for a maximum of 1 second.
# The host can be slow to reply. The default is 0, which checks the table one time.
settings.ARP_TIMEOUT = 1.0
print(get_mac_address(ip="192.168.0.1"))

# Get the name of the system's default network interface
from getmac import get_default_interface
print(get_default_interface())
```

## Terminal examples
```bash
getmac --help
getmac --version

# With no arguments, show the MAC address of the default interface
getmac

# Start getmac as a Python module
python3 -m getmac

# Give an interface name, an IPv4 or IPv6 address, or a hostname
getmac --interface ens33
getmac --ip 192.168.0.1
getmac --ip6 ::1
getmac --hostname home.router

# Start getmac as a Python module, with the short forms of the arguments
python -m getmac -i 'Ethernet 4'
python -m getmac -4 192.168.0.1
python -m getmac -6 ::1
python -m getmac -n home.router

# To get the MAC address of a remote host, the host must be in the ARP table.
# By default, getmac sends a UDP packet to a high port on the host (55555) to populate the table.
# To disable this, use --no-network-requests (or -N):
getmac --no-network-requests --ip 192.168.0.1
python -m getmac -N -n home.router

# Show the log messages
getmac --verbose

# Set the debug level with '-d'
getmac -v --debug
python -m getmac -v -d -i enp11s4
python -m getmac -v -dd -n home.router

# Change the UDP port that getmac sends the packet to, to populate the ARP table
getmac --ip 192.168.0.1 --override-port 9001

# After getmac sends the UDP packet, check the ARP table again for a maximum of 1 second
getmac --ip 192.168.0.1 --arp-timeout 1

# Replace the platform that getmac detects with '--override-platform'.
# This is useful to debug problems. It is also useful when you know that a method
# for a different platform works on this platform.
# All values that platform.system() returns are valid.
getmac -i eth0 --override-platform linux
getmac --ip 192.168.0.1 --override-platform windows

# Use one specific method, even if the method does not work on this system
getmac -v -dddd --ip 192.168.0.1 --force-method ctypeshost
```

## API: `get_mac_address()`
- `interface`: the name of a network interface on the system
- `ip`: the IPv4 address of a remote host
- `ip6`: the IPv6 address of a remote host
- `hostname`: the hostname of a remote host
- `network_request`: whether getmac sends a network request. In most conditions, the request populates the ARP table (IPv4) or NDP table (IPv6) that getmac uses to find the MAC of a remote host.
    - Disable it to use only the entries that are already in the table, or if you must prevent network traffic.
    - The network request is an empty UDP packet to a high port. The default port is `55555`. To change the port, set `getmac.variables.Settings.PORT` to a different integer.
    - On Windows, getmac also sends a UDP packet to `1.1.1.1:53` to find the default interface. This IP address is [Cloudflare's DNS server](https://www.cloudflare.com/learning/dns/what-is-1.1.1.1/).

## Configuration
- `logging.getLogger("getmac")`: getmac records messages and errors to the `getmac` logger of the Python [logging](https://docs.python.org/3/library/logging.html) module. To configure the logger, use [logging.basicConfig()](https://docs.python.org/3/library/logging.html#logging.basicConfig), or add handlers to the `"getmac"` logger.
- `getmac.variables.Settings.DEBUG`: an integer that controls the debug output. A higher value gives more output.
- `getmac.variables.Settings.PORT`: the UDP port that getmac sends a packet to, to populate the ARP or NDP table. For more information, see the `network_request` argument of `get_mac_address()`.
- `getmac.variables.Settings.ARP_TIMEOUT`: the maximum time, in seconds, that getmac checks the ARP or NDP table for a host after it sends the UDP packet. The system adds the host to the table only when the host replies. The reply can arrive after getmac checks the table. The default is `0`, which checks the table one time and does not wait. A lookup of a host that does not reply takes this much more time.
- `getmac.variables.Settings.OVERRIDE_PLATFORM`: replaces the detected platform with this value, for example `"linux"`, `"windows"` or `"freebsd"`. All values that `platform.system()` returns are valid.
- `getmac.variables.Settings.FORCE_METHOD`: the name of a method that getmac must use, for example `"IpNeighborShow"`. getmac uses this method for every lookup, and ignores its type and platforms. getmac does **not** call `Method.test()` for it. `getmac.getmac.METHODS` lists the available methods.

## Features
- Pure Python, with no compiled C-extensions
- Python 3.9 and later
- No dependencies, and a small package size
- Supports most platforms
- Supports CPython and [PyPy](https://www.pypy.org/)
- Has a command-line tool, when you install it as a package
- MIT license

## Notes
- If you give none of the arguments, getmac uses the default network interface of the system. If getmac cannot find the default interface, or the default interface has no MAC, getmac uses a different interface. It uses the first interface that has a MAC and is not a loopback interface. For example, the default interface can be missing when the system has no routes. A VPN tunnel is an example of an interface with no MAC. If no interface agrees with these conditions, the result is `None`. On Windows, getmac uses only the default interface.
- A "remote host" is a host in your local layer 2 network. Other names for this network are "broadcast domain", "LAN", and "VLAN". As far as I know, no reliable method gets the MAC address of a remote host outside the LAN. If you know a method, please [open a GitHub issue](https://github.com/GhostofGoes/getmac/issues) or send me an email. I would like to be wrong about this.
- You can use only one of the first four arguments. `network_request` has no effect with the `interface` argument. Thus, a script can set it for all lookups.
- getmac assumes that the physical transport is Ethernet (802.3). I do not test or consider other transports at this time, such as Wi-Fi (802.11). I plan to address this in the future. Pull requests and issues about this are welcome, and error reports also.
- **getmac catches most exceptions and returns `None`.** If you have problems, set `DEBUG` to `1` or more to get more information. If the problem continues, please create an [issue on GitHub](https://github.com/GhostofGoes/getmac/issues), and include the output with `DEBUG` enabled. Since 1.0.0, getmac raises a `RuntimeError` when no method can do the lookup. This occurs when no method agrees with the type of lookup and the platform, or when all those methods fail their test.

## Commands and techniques by platform
- Windows
    - Commands: `getmac.exe`, `ipconfig.exe`, `arp.exe`, `netsh.exe`, `wmic.exe`
    - Libraries: `ctypes`, `socket`
    - Default interfaces: `netsh.exe`
- Linux/Unix
    - Commands: `arp`, `ip`, `ifconfig`, `netstat`, `ip link`, `arping` (both iputils and Habet's variants)
    - Libraries:  `fcntl`, `socket`
    - Files: `/sys/class/net/{iface}/address`, `/proc/net/arp`
    - Default interfaces: `/proc/net/route`, `route`, `ip route list`
- HP-UX:
    - Commands: `lanscan`
- Mac OSX (Darwin)
    - Commands: `networksetup`, `arping`
    - Many of the same commands as Linux
- WSL
    - Windows commands are used for remote hosts
    - Unix commands are used for interfaces
- OpenBSD
    - Commands: `ifconfig`, `arp`
    - Default interfaces: `route`
- FreeBSD
    - Commands: `ifconfig`, `arp`
    - Default interfaces: `netstat`
- Android
    - The same commands and files as Linux, where they're available. See the note on Android below.

## Platforms currently supported
All or almost all features should work on the supported platforms. Other versions of the same family or distribution may work, but I did not test them. They may have bugs or missing features.

- Windows
    - Desktop: 7, 8, 8.1, 10, 11 (thanks @StevenLooman for testing Windows 11!)
    - Server: 2025, 2022
    - Partially supported (untested): 2000, XP, Vista
- Linux distros
    - CentOS/RHEL 6+
    - Ubuntu 16.04+ (15.10 and older should work, but are untested)
    - Fedora (24+)
- Mac OSX (Darwin)
    - The latest release, though OSX 14 and 13 have been tested with success.
- Android (6+)
    - Newer versions of Android do not have many of the commands that getmac uses. They also restrict access to network information. Thus, getmac may find nothing. [BusyBox](https://busybox.net/), or the `iproute2` and `net-tools` packages from [Termux](https://termux.dev/), add the missing commands. Android's restrictions can still block these commands.
- Windows Subsystem for Linux (WSL)
- FreeBSD (11+)
- OpenBSD
- Docker
- BusyBox. BusyBox is not a platform, but some of the methods work with it.

## Legacy Python versions
For an old Python (3.8 and earlier) or an old interpreter, install an older version of `getmac` that supports it. The wheels are on the [GitHub releases page](https://github.com/GhostofGoes/getmac/releases) and on PyPI. To install them from PyPI, you may need a current version of `pip` and some extra arguments.

- Python 2.5: `get-mac==0.5.0`
- Python 2.6: `getmac==0.6.0`
- Python 2.7: `getmac<1.0.0`
- Python 3.2: `get-mac==0.3.0`
- Python 3.3: `get-mac==0.3.0`
- Python 3.4: `getmac<1.0.0`
- Python 3.5: `getmac<1.0.0`
- Python 3.6: `getmac<1.0.0`
- Python 3.7: `getmac<1.0.0`
- Python 3.8: `getmac<1.0.0`

NOTE: these older versions do not have many of the performance improvements, platform support, and bug fixes of later releases. They usually work, but not as well.

## Docker
A Docker image of the `getmac` command is available from the [GitHub Container Registry](https://github.com/GhostofGoes/getmac/pkgs/container/getmac), for `linux/amd64` and `linux/arm64`. The container runs `getmac` as an unprivileged user (`nobody`). The container gives all arguments to `getmac`.

```bash
docker run --rm ghcr.io/ghostofgoes/getmac --help
docker run --rm ghcr.io/ghostofgoes/getmac --version
docker run --rm ghcr.io/ghostofgoes/getmac -n localhost
```

The `latest` tag is the newest stable release. Each release also has tags for its version, for example `1.0.0`, `1.0`, and `1`. Pre-releases have only the tag for their version. The `edge` tag is built from the `main` branch.

By default, the container is on the bridge network of Docker. Thus, the container sees its own interfaces and its own ARP table, not the interfaces and ARP table of the host.

- On Linux, to look up the interfaces of the host, use `--network host`.
- In bridge mode, to read the ARP table of the host, add `-v /proc/1/net/arp:/host/arp:ro -e ARP_PATH=/host/arp`.
- With Docker Desktop on macOS and Windows, the container sees only the network of the Docker VM, not the network of your computer.
- IPv6 lookups (`-6`) need a Docker network with IPv6 enabled.

```bash
docker run --rm --network host ghcr.io/ghostofgoes/getmac
docker run --rm -v /proc/1/net/arp:/host/arp:ro -e ARP_PATH=/host/arp ghcr.io/ghostofgoes/getmac -4 192.168.0.1
```

To build the image yourself, see the [Docker section of the contribution guide](https://ghostofgoes.github.io/getmac/contributing.html#docker).

## Caveats
- On some platforms, getmac can be slow, because it uses many regular expressions.
- The tests do not cover all platforms. If you have problems, your platform may be one that I did not test. Please open a GitHub issue, and I will help.

## Known Issues
- Linux, WSL: getmac cannot get the MAC address of the IP address of a local interface. For example, `getmac --ip 10.0.0.4` fails if `10.0.0.4` is the IP address of a local interface. Other POSIX systems may have this issue also.
- getmac does not support hostnames for IPv6 devices yet.
- Windows: `ipconfig.exe` is a fallback for when `getmac.exe` does not work. It finds interfaces by name only when its output is in English, because Windows translates the adapter headers.
- IPv6 support is good, but it is less complete than IPv4 support in some areas. I also test IPv6 less on the supported platforms.

## Background and history
The Python standard library has many networking modules, such as `urllib`, `ipaddress`, `ftplib`, `telnetlib`, and `ssl`. But I found that it had no way to get a MAC address. I wrote this package for two needs. The first need was to get the MAC address of hosts on the network without admin permissions. The second need was to get the addresses of local interfaces on all platforms.

In Fall 2018, the package name changed from `get-mac` to `getmac`. This changed the package name, the CLI script, and some of the documentation. The core library code did not change. I will update both package names on PyPI, but please use `getmac`.

In Summer 2020, I changed the code to a class-based structure. This made getmac much faster and more accurate. See [rewrite.md](https://github.com/GhostofGoes/getmac/blob/main/docs/misc_docs/rewrite.md) for details.

## Contributing
Contributors are more than welcome! See the [contribution guide](https://ghostofgoes.github.io/getmac/contributing.html) to get started, and checkout the [todo list](https://github.com/GhostofGoes/getmac/blob/main/docs/misc_docs/TODO.md) for a full list of tasks and bugs.

Before submitting a PR, please make sure you've completed the [pull request checklist](https://ghostofgoes.github.io/getmac/contributing.html#checklist-before-submitting-a-pull-request)!

The [Python Discord server](https://discord.gg/python) is a good place to ask questions or discuss the project (handle: `@knownerror`).

## Contributors
- Christopher Goes (@ghostofgoes) - Author and maintainer
- Calvin Tran (@cyberhobbes) - Windows interface detection improvements
- Daniel Flanagan (@FlantasticDan) - Code cleanup
- @emadmahdi - Android fixes
- Izra Faturrahman (@Frizz925) - Unit tests using the platform samples
- Jose Gonzalez (@Komish) - Docker container and Docker testing
- @fortunate-man - Awesome usage videos
- @martmists - legacy Python compatibility improvements
- @hargoniX - scripts and specfiles for RPM packaging
- Ville Skyttä (@scop) - arping lookup support
- Tomasz Duda (@tomaszduda23) - support for docker in network bridge mode
- Steven Looman (@StevenLooman) - Windows 11 testing
- Reimund Renner (@raymanP) - macOS fixes
- Simone Chemelli (@chemelli74) - py.typed the library

## Sources
Many of the methods used to acquire an address and the core logic framework are attributed to the CPython project's UUID implementation.

- https://github.com/python/cpython/blob/master/Lib/uuid.py
- https://github.com/python/cpython/blob/2.7/Lib/uuid.py

### Other notable sources
- [_unix_fcntl_by_interface](https://stackoverflow.com/a/4789267/2214380)
- [_windows_get_remote_mac_ctypes](https://github.com/ActiveState/code/tree/master/recipes/Python/347812_Get_MAC_address_remote)
- [String joining](https://stackoverflow.com/a/3258612/2214380)
- [Facter](https://github.com/puppetlabs/facter) - Command output examples from Facter are leveraged for better test coverage
- [GLPI Agent](https://github.com/glpi-project/glpi-agent) - Command output examples from GLPI Agent are leveraged for better test coverage

## License
The code is licensed MIT. The test data contains Apache 2.0 and GPLv2 licensed files, in the `tests/samples/third_party/` directory. These files are not included in the packages published to PyPI.
