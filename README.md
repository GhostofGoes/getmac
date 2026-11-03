
<p align="center">
  <a href="https://pypi.org/project/getmac/"><img alt="PyPI - Current Version" src="https://img.shields.io/pypi/v/getmac?label=PyPI"></a>
  <img alt="Python Version" src="https://img.shields.io/badge/Python-3.9|3.10|3.11|3.12|3.13|3.14|3.15-blue.svg">
  <a href="https://pepy.tech/project/getmac"><img alt="Weekly PyPI downloads" src="https://pepy.tech/badge/getmac/week"></a>
  <a href="https://pepy.tech/project/getmac"><img alt="PyPI downloads" src="https://pepy.tech/badge/getmac"></a>
  <br>
  <a href="https://github.com/GhostofGoes/getmac/actions"><img alt="GitHub Actions Pipeline Status" src="https://github.com/ghostofgoes/getmac/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://codecov.io/github/GhostofGoes/getmac"><img alt="codecov" src="https://codecov.io/github/GhostofGoes/getmac/branch/main/graph/badge.svg?token=5NxlAE9eGY"></a>
  <a href="https://www.bestpractices.dev/projects/9388"><img alt="OpenSSF Best Practices" src="https://www.bestpractices.dev/projects/9388/badge"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/GhostofGoes/getmac"><img alt="OpenSSF Scorecard" src="https://api.scorecard.dev/projects/github.com/GhostofGoes/getmac/badge"></a>
  <br>
  <a href="https://pdm-project.org"><img alt="PDM-managed" src="https://img.shields.io/endpoint?url=https%3A%2F%2Fcdn.jsdelivr.net%2Fgh%2Fpdm-project%2F.github%2Fbadge.json"></a>
  <a href="https://github.com/astral-sh/ruff"><img alt="Ruff" src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json"></a>
</p>

Pure-Python package to get the MAC address of network interfaces and hosts on the local network.

It provides a platform-independent interface to get the MAC addresses of:

- System network interfaces (by interface name)
- Remote hosts on the local network (by IPv4/IPv6 address or hostname)

It provides one primary function, `get_mac_address()`, and a command line tool, `getmac`.

The full documentation is at https://ghostofgoes.github.io/getmac/, including the [usage guide](https://ghostofgoes.github.io/getmac/usage.html), the [command line reference](https://ghostofgoes.github.io/getmac/cli.html), [troubleshooting](https://ghostofgoes.github.io/getmac/troubleshooting.html), and how to [upgrade from 0.9.x](https://ghostofgoes.github.io/getmac/upgrading.html).

[![asciicast](https://asciinema.org/a/n3insrxfyECch6wxtJEl3LHfv.svg)](https://asciinema.org/a/n3insrxfyECch6wxtJEl3LHfv)


## Should you use this package?
If you only need the addresses of network interfaces, have a limited set of platforms to support, and are able to handle C-extension modules, then you should instead check out the excellent [netifaces](https://pypi.org/project/netifaces/) package by Alastair Houghton ([@al45tair](https://github.com/al45tair)). It's significantly faster (thanks to it being C code) and has been around a long time and seen widespread usage. Unfortunately, it hasn't been maintained since [May 2021](https://github.com/al45tair/netifaces/commit/ec55b59e27542776f55e0f9e3213a75bf8e0f367), so it may not be a great choice for new projects. Another great option that fits these requirements is the well-known and battle-hardened [psutil](https://github.com/giampaolo/psutil) package by Giampaolo Rodola.

If the only system you need to run on is Linux, you can run as root, and C-extension modules are fine, then you should instead check out the [arpreq](https://pypi.org/project/arpreq/) package by Sebastian Schrader. In some cases it can be significantly faster.

If you want to use `psutil`, `scapy`, or `netifaces`, I have examples of how to do so in a [GitHub Gist](https://gist.github.com/GhostofGoes/0a8e82930e75afcefbd879a825ba4c26).

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
`apt` may have it available, depending on your distro (see packaging status below):

```bash
sudo apt install getmac
```

### OS Packaging Status

[![Packaging status](https://repology.org/badge/vertical-allrepos/getmac.svg)](https://repology.org/project/getmac/versions)

### Docker
There's also a [Docker image](#docker) of the `getmac` command. Older Pythons (3.8 and older) need an [older version of getmac](#legacy-python-versions).

## Python examples
```python
from getmac import get_mac_address, settings

eth_mac = get_mac_address(interface="eth0")
win_mac = get_mac_address(interface="Ethernet 3")
ip_mac = get_mac_address(ip="192.168.0.1")
ip6_mac = get_mac_address(ip6="fe80::1")
host_mac = get_mac_address(hostname="home.router")
updated_mac = get_mac_address(ip="10.0.0.1", network_request=True)

# Enable debugging
settings.DEBUG = 2  # DEBUG level 2
print(get_mac_address(interface="Ethernet 3"))

# Change the UDP port used for updating the ARP table (UDP packet)
settings.PORT = 44444  # Default is 55555
print(get_mac_address(ip="192.168.0.1", network_request=True))

# After sending the UDP packet, keep checking the ARP table for the host for up to
# 1 second, since it can take a moment to reply. Default is 0 (check once).
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

# Invoking with no arguments will return MAC of the default interface
getmac

# Usage as a module
python3 -m getmac

# Interface names, IPv4/IPv6 addresses, or Hostnames can be specified
getmac --interface ens33
getmac --ip 192.168.0.1
getmac --ip6 fe80::1
getmac --hostname home.router

# Running as a Python module with shorthands for the arguments
python -m getmac -i 'Ethernet 4'
python -m getmac -4 192.168.0.1
python -m getmac -6 fe80::1
python -m getmac -n home.router

# Getting the MAC address of a remote host requires the ARP table to be populated.
# By default, getmac will populate the table by sending a UDP packet to a high port on the host (defaults to 55555).
# This can be disabled with --no-net (or -N), as shown here:
getmac --no-net --ip 192.168.0.1
python -m getmac -N -n home.router

# Enable output messages
getmac --verbose

# Debug levels can be specified with '-d'
getmac -v --debug
python -m getmac -v -d -i enp11s4
python -m getmac -v -dd -n home.router

# Change the UDP port used for populating the ARP table when getting the MAC of a remote host
getmac --ip 192.168.0.1 --override-port 9001

# Keep checking the ARP table for the host for up to 1 second after sending the UDP packet
getmac --ip 192.168.0.1 --arp-timeout 1

# The platform detected by getmac can be overridden via '--override-platform'.
# This is useful when debugging issues or if you know a method
# for a different platform works on the current platform.
# Any values returned by platform.system() are valid.
getmac -i eth0 --override-platform linux
getmac --ip 192.168.0.1 --override-platform windows

# Force a specific method to be used, regardless of the consequences or if it even works
getmac -v -dddd --ip 192.168.0.1 --force-method ctypeshost
```

The MAC is printed to stdout and the exit code is `0`. If nothing was found, nothing is printed and the exit code is `1`. Bad arguments (e.g. using two lookup options at once) exit with `2`. Log messages (`-v`) go to stderr.

## API: `get_mac_address()`
- `interface`: Name of a network interface on the system
- `ip`: IPv4 address of a remote host
- `ip6`: IPv6 address of a remote host
- `hostname`: Hostname of a remote host
- `network_request`: If a network request should be made to update and populate the ARP/NDP table of remote hosts used to lookup MACs in most circumstances. Disable this if you want to just use what's already in the table, or if you have requirements to prevent network traffic.
    - The network request is an empty UDP packet sent to a high port, `55555` by default. This can be changed by setting `getmac.settings.PORT` to the desired integer value.
    - If `arping` is installed (Linux and macOS), or on Windows, an ARP request is sent instead of the UDP packet (IPv4 only). On Linux, the ARP table file is read first, and nothing is sent if it has a complete entry for the host.
    - With no arguments on Windows, getmac connects a UDP socket to `1.1.1.1:53` to find the IP of the default interface (Note: the IP is [CloudFlare's DNS server](https://www.cloudflare.com/learning/dns/what-is-1.1.1.1/)). Nothing is sent, since connecting a UDP socket only picks a route. Skipped with `network_request=False`.

Only one of the first four arguments can be used at a time. `ip` and `ip6` also accept objects from the standard library's `ipaddress` module (`IPv4Address`, `IPv4Interface`, `IPv6Address`, `IPv6Interface`), and all four accept `bytes` (decoded as UTF-8).

## Configuration
Settings are attributes of `getmac.settings` (`from getmac import settings`). Set them before calling `get_mac_address()`.

- `logging.getLogger("getmac")`: Runtime messages and errors are recorded to the `getmac` logger using Python's [logging](https://docs.python.org/3/library/logging.html) module. They can be configured by using [logging.basicConfig()](https://docs.python.org/3/library/logging.html#logging.basicConfig) or adding handlers to the `"getmac"` logger.
- `settings.DEBUG`: integer value that controls debugging output. The higher the value, the more output you get (`0` is the default, `4` is roughly the highest).
- `settings.PORT`: UDP port used to populate the ARP/NDP table (see the documentation of the `network_request` argument in `get_mac_address()` for details). Default is `55555`.
- `settings.ARP_TIMEOUT`: How long to keep checking the ARP/NDP table for a host after sending the UDP packet, in seconds. The host's entry is only added once it replies, which can take longer than getmac takes to check. Default is `0` (check once, without waiting). Lookups of hosts that don't reply take this much longer.
- `settings.COMMAND_TIMEOUT`: How long to wait for a command that getmac runs (such as `arp` or `ipconfig.exe`) to finish, in seconds. A command that takes longer is stopped, and the next method is tried. Default is `15`. `None` or `0` waits for as long as the command takes.
- `settings.OVERRIDE_PLATFORM`: Override the platform detection with the given value (e.g. `"linux"`, `"windows"`, `"freebsd"`, etc.). Any value returned by `platform.system()` is valid.
- `settings.FORCE_METHOD`: Force a specific method to be used, e.g. `"IpNeighborShow"`. This will be used regardless of its method type or platform compatibility, and `Method.test()` will NOT be checked! The list of available methods is in `getmac.getmac.METHODS` (and in the [API reference](https://ghostofgoes.github.io/getmac/api.html)).
- `ARP_PATH` (environment variable): The file to read the ARP table from, instead of `/proc/net/arp`. Linux only, and read when getmac is imported. Useful in containers.

## Features
- Pure-Python (no compiled C-extensions required!)
- Python 3.9+
- Lightweight, with no dependencies and a relatively small package size (no binary extensions)
- Supports most platforms with NO binary extensions required!
- Supports CPython and [PyPy](https://www.pypy.org/)
- Provides a simple command line tool (when installed as a package)
- MIT licensed!

## Notes
- If none of the arguments are selected, the default network interface for the system will be used. If the default network interface cannot be determined (for example, if there aren't any routes) or doesn't have a MAC (for example, a VPN tunnel), then the first interface that has a MAC and isn't a loopback interface is used. If there isn't one, `None` is returned. On Windows, only the default interface is used, and with network requests enabled, the IP of the default interface is found first (a UDP socket is connected to `1.1.1.1:53`, but nothing is sent) and looked up as a host.
- `hostname="localhost"` (`-n localhost`) and `ip="127.0.0.1"` (`-4 127.0.0.1`) return `"00:00:00:00:00:00"`, the MAC of the loopback interface. Other spellings, such as `::1`, `127.0.0.2`, `LOCALHOST`, or the host's own name, aren't short-circuited and return `None`.
- "Remote hosts" refer to hosts in your local layer 2 network, also commonly referred to as a "broadcast domain", "LAN", or "VLAN". As far as I know, there is not a reliable method to get a MAC address for a remote host external to the LAN. If you know any methods otherwise, please [open a GitHub issue](https://github.com/GhostofGoes/getmac/issues) or shoot me an email, I'd love to be wrong about this.
- The first four arguments are mutually exclusive. `network_request` does nothing with `interface` (so it's safe to set in a script). With `ip`, `ip6` and `hostname`, it allows the ARP request or UDP packet. With no arguments, it only matters on Windows, for the socket step above.
- The physical transport is assumed to be Ethernet or Wi-Fi. Others, such as Bluetooth or cellular, may work, but they're untested. I'm definitely open to pull requests or issues related to this, including error reports.
- **Most exceptions are handled silently and returned as `None`.** If you run into problems, set `DEBUG` to `1` or higher (or use `getmac -v -dddd` on the command line) to get more information about what's happening. If you're still having issues, check the [troubleshooting guide](https://ghostofgoes.github.io/getmac/troubleshooting.html), then please create an [issue on GitHub](https://github.com/GhostofGoes/getmac/issues) and include the output with `DEBUG` enabled.
- As of 1.0.0, a `RuntimeError` is raised if no methods match the type of request and platform, or if all matching methods fail their test (in other words, none of them work). On a platform getmac doesn't know, it falls back to generic methods and still shows a `RuntimeWarning` when it does. A `ValueError` is raised for an `ipaddress` network (e.g. `IPv4Network`), since getmac needs a host, not a network.
- The first call is slower than the rest. getmac checks which methods work on your system the first time it needs one, and remembers the result for the rest of the process.

## Commands and techniques by platform
The [platforms page](https://ghostofgoes.github.io/getmac/platforms.html) lists the methods getmac tries on each platform, in order, and the [API reference](https://ghostofgoes.github.io/getmac/api.html) documents each method.

- Windows
    - Commands: `getmac.exe`, `ipconfig.exe`, `arp.exe`, `netsh.exe`, `wmic.exe`
    - Libraries: `ctypes`, `socket`
    - Default interfaces: `netsh.exe`
- Linux/Unix
    - Commands: `arp`, `ip`, `ifconfig`, `netstat`, `ip link`, `arping` (iputils, Habets', and BusyBox variants)
    - Libraries:  `fcntl`, `socket`
    - Files: `/sys/class/net/{iface}/address`, `/proc/net/arp`
    - Default interfaces: `/proc/net/route`, `route`, `ip route list`
- HP-UX:
    - Commands: `lanscan`
- macOS (Darwin)
    - Commands: `networksetup`, `arping`, `ndp` (IPv6 hosts)
    - Many of the same commands as Linux
- WSL1
    - Unix commands and files are used for interfaces
    - Windows `arp.exe` is used for IPv4 hosts
- WSL2
    - The same as Linux
- OpenBSD
    - Commands: `ifconfig`, `arp`, `ndp` (IPv6 hosts)
    - Default interfaces: `route`
- FreeBSD
    - Commands: `ifconfig`, `arp`, `ndp` (IPv6 hosts)
    - Default interfaces: `route`, `netstat`
- NetBSD
    - Commands: `ifconfig`, `arp`, `ndp` (IPv6 hosts)
    - Default interfaces: `route`
- DragonFly BSD
    - Commands: `ifconfig`, `arp`, `ndp` (IPv6 hosts)
    - Default interfaces: `route`
- Solaris and illumos
    - Commands: `dladm`, `netstat`, `ifconfig`, `arp`
    - Default interfaces: `route`
- Android
    - The same commands and files as Linux, where they're available. See the note on Android below.

## Platforms currently supported
All or almost all features should work on "supported" platforms. While other versions of the same family or distro may work, they are untested and may have bugs or missing features.

- Windows
    - Desktop: 7, 8, 8.1, 10, 11 (thanks @StevenLooman for testing Windows 11!)
    - Server: 2025, 2022
    - Partially supported (untested): 2000, XP, Vista
- Linux distros
    - CentOS/RHEL 6+
    - Ubuntu 16.04+ (15.10 and older should work, but are untested)
    - Fedora (24+)
- macOS (Darwin)
    - The latest release, though macOS 14 and 13 have been tested with success.
- Android (6+)
    - Newer versions of Android don't have many of the commands getmac uses, and restrict access to network information, so getmac may not find anything. Installing [BusyBox](https://busybox.net/) or the [Termux](https://termux.dev/) `iproute2` and `net-tools` packages adds the missing commands, but they can still be blocked by Android's restrictions.
- Windows Subsystem for Linux (WSL)
- FreeBSD (11+)
- OpenBSD
- NetBSD (9.3+)
- DragonFly BSD (6.4+)
- Oracle Solaris 11.4
- illumos distros: OmniOS (r151054+), OpenIndiana (2026.04+). Others like SmartOS should work, but are untested.
- HP-UX (untested): interface lookups only, via `lanscan`
- Docker
- BusyBox (not technically a platform, but several of the methods work on this platform)

## Legacy Python versions
If you are running an old Python (3.8 and older) or interpreter, then you can install an older version of `getmac` that supported that version. The wheels are available in the [GitHub releases](https://github.com/GhostofGoes/getmac/releases), or from PyPI with a current version of `pip` and some special arguments.

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

NOTE: these versions do not have many of the performance improvements, platform support, and bug fixes that came with later releases. They generally work, just not as well. However, if you're using such an old Python, you probably don't care about all that :)

## Docker
A Docker image of the `getmac` command is published to the [GitHub Container Registry](https://github.com/GhostofGoes/getmac/pkgs/container/getmac) for `linux/amd64` and `linux/arm64`. The container runs `getmac` as an unprivileged user (`nobody`), and any arguments are passed to it.

```bash
docker run --rm ghcr.io/ghostofgoes/getmac --help
docker run --rm ghcr.io/ghostofgoes/getmac --version
docker run --rm ghcr.io/ghostofgoes/getmac -n localhost
```

The `latest` tag is the newest stable release, and releases are also tagged with their version (e.g. `1.0.0`, `1.0`, and `1`). Pre-releases are only tagged with their version. The `edge` tag is built from the `main` branch.

By default the container is on Docker's bridge network, so it sees its own interfaces and ARP table, not the host's. On Linux, use `--network host` to look up the host's interfaces. In bridge mode, add `-v /proc/1/net/arp:/host/arp:ro -e ARP_PATH=/host/arp` to read the host's ARP table. With Docker Desktop on macOS and Windows, the container only sees the Docker VM's network, not your computer's. IPv6 lookups (`-6`) need a Docker network with IPv6 enabled.

```bash
docker run --rm --network host ghcr.io/ghostofgoes/getmac
docker run --rm -v /proc/1/net/arp:/host/arp:ro -e ARP_PATH=/host/arp ghcr.io/ghostofgoes/getmac -4 192.168.0.1
```

To build the image yourself, see the [Docker section of the contribution guide](https://ghostofgoes.github.io/getmac/contributing.html#docker).

## Known Issues
- Linux, WSL: Getting the mac of a local interface IP does not currently work (`getmac --ip 10.0.0.4` will fail if `10.0.0.4` is the IP address of a local interface). This issue may be present on other POSIX systems as well.
- Hostnames for IPv6 devices are not yet supported.
- WSL1: remote IPv6 hosts aren't supported yet. Windows' `arp.exe` is used for IPv4 hosts, and `netsh.exe` isn't used on WSL1 yet.
- IPv6 link-local addresses can carry a zone (`fe80::1%en0` or `fe80::1%2`), but only macOS and the BSDs and Solaris and illumos use it. On Linux and Windows, pass the address without a zone.
- Windows: `ipconfig.exe` (a fallback for when `getmac.exe` doesn't work) only finds interfaces by name in English output, since the adapter headers are translated.
- IPv6 support is good but lags behind IPv4 in some places and isn't as well-tested across the supported platform set.
- Platform test coverage is imperfect. If you're having issues, then you might be using a platform I haven't been able to test. Keep calm, open a GitHub issue, and I'd be more than happy to help.

## Background and history
The Python standard library has a robust set of networking functionality, such as `urllib`, `ipaddress`, `ftplib`, `telnetlib`, `ssl`, and more. Imagine my surprise, then, when I discovered there was not a way to get a seemingly simple piece of information: a MAC address. This package was born out of a need to get the MAC address of hosts on the network without needing admin permissions, and a cross-platform way get the addresses of local interfaces.

In Fall 2018 the package name changed to `getmac` from `get-mac`. This affected the package name, the CLI script, and some of the documentation. There were no changes to the core library code. While both package names will updated on PyPI, the use of `getmac` is preferred.

In Summer 2020, the code was significantly refactored, moving to a class-based structure and significantly improving performance and accuracy. See [rewrite.md](https://github.com/GhostofGoes/getmac/blob/main/docs/misc_docs/rewrite.md) for details.

## Contributing
Contributors are more than welcome! See the [contribution guide](https://ghostofgoes.github.io/getmac/contributing.html) to get started, and checkout the [todo list](https://github.com/GhostofGoes/getmac/blob/main/docs/misc_docs/TODO.md) for a full list of tasks and bugs. If you want to add support for a new command or platform, there's a guide to [adding a new method](https://ghostofgoes.github.io/getmac/adding_methods.html).

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
- [Ansible](https://github.com/ansible/ansible) - NetBSD `ifconfig -a` output from Ansible's unit tests is leveraged for better test coverage
- [Ohai](https://github.com/chef/ohai) - FreeBSD `route -n get default` output from Chef Ohai's specs is leveraged for better test coverage
- [jackpal/gateway](https://github.com/jackpal/gateway) - FreeBSD `netstat -rn` output from its route tables is leveraged for better test coverage

## License
The code is licensed MIT. The test data contains Apache 2.0, BSD 3-Clause, GPLv2, and GPLv3 (Ansible) licensed files, in the `tests/samples/third_party/` directory. These files are not included in the packages published to PyPI.
