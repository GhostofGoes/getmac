
# Bugs or potential issues
* [X] Interface IP on Ubuntu gets loopback, instead of primary interface
* [ ] Unicode handling. UNICODE option needed for non-english locales? (Is LC_ALL working?)
* [ ] Are there ever cases where loopback != FF:FF:FF:FF:FF:FF?
* [ ] Remote host that is actually an interface should resolve to localhost MAC
* [ ] Detect if an interface exists before trying to find it's MAC.
Currently, the call is penalized with a slow run since it tries every method before failing.

# Platform support

## Windows

### Remote hosts
* [ ] IPv6: `netsh int ipv6 show neigh`
* [ ] IPv4: `netsh int ipv4 show neigh`
* [ ] `arping`
* [ ] Windows API

### Interface MACs
* [ ] `netsh int ipv6`
* [x] `ipconfig`
* [x] `wmic`: `wmic NICCONFIG where IpEnabled=True get Description IPAddress MACAddress`
             This will also work for interface indices
* [ ] Windows API

### Default Interfaces
This is going to be a bit more complicated since the highest
metric routes are going to be IP addresses and not interfaces.
We'll have to resolve those to an interface, then select that
interface as the default route.
* [ ] IPv4: `netsh interface ipv4 show route`
* [ ] IPv6: `netsh interface ipv6 show route`
* [ ] `ipconfig`
* [ ] IPv4: `route print -4`
* [ ] IPv6: `route print -6`
* [ ] Windows API

## Non-Windows (POSIX, etc.)
* [ ] `arping`: investigate for remote macs
* [ ] `fcntl`: IPv6?
* [ ] `ip addr`

## Platforms
* [x] Linux
* [x] Windows (modern)
* [x] Darwin (Mac OS)
* [x] Windows Subsystem for Linux (WSL)
* [x] Docker (inside Docker containers)
* [ ] Alpine Linux (test + add to tests)
* [ ] Raspberry Pi (test)
* [ ] OpenBSD
* [ ] FreeBSD
* [ ] Android (Which you could argue *correctly* is Linux)
* [ ] Solaris


# Features

## IPv6
* [ ] Support for IPv6 hostname resolution
    * [ ] Use `socket.getaddrinfo` instead of `socket.gethostbyname`
          to resolve a hostname to an IP address.

## Performance
* [ ] Profiling
    * [ ] CPU usage
    * [ ] Memory usage
    * [ ] Run time/load time
* [ ] Cache results on regex-heavy functions (add a arg to disable this behavior)
* [ ] Improve performance (spend a lot of time on performance tuning with the regexes)

## Misc.
* [X] make_arp_request
* [ ] Add ability to match user-provided arguments case-insensitively
* [ ] Add ability to get the mac address of a socket's interface
* [ ] Add support for Unix and Windows interface indices as a separate
      argument to `get_mac_address`. On Windows, we could use `wmic`,
      while on Unix and Python 3 we can use `socket.if_indextoname()`.
* [ ] Ignore case on regular expressions? (Better matching possibly)
* [ ] Test against non-ethernet interfaces (WiFi, LTE, etc.)
* [ ] Threading (spin out all attempts, plus make itself thread-friendly)
* [ ] asyncio-friendly?


# Tests
* [ ] Unit tests for helper methods
* [ ] Mocked unit tests for core methods
* [ ] Run unit tests on all of the samples I've collected thus far
* [ ] Need samples from many more platforms to build effective tests
* [ ] Functional tests using Bats for all Python versions
* [x] Appveyor testing
* [ ] Unittesting of Python 2.6 (since we have it disabled on CLI tests)
* [ ] Add MyPy checking to required tests
* [ ] Add profiling to tests. If average of multiple runs goes
 above a certain threshold, the tests fail.

# Documentation
* [x] List of related works in README (shoutouts)
* [x] List of 3rd-party packages that are attempted
* [ ] List of methods that are attempted
* [x] Improve documentation on what it can and can't do
      (and educate the user on what MACs and broadcasts are)
* [ ] Sphinx documentation
* [ ] Man page
* [ ] HTML web documentation on ReadTheDocs
* [ ] Screenshots
* [x] ASCII Cinema capture of usage
* [ ] Add documentation and other links to project_urls in setup.py

# Code/Other
* [ ] Add mypy-style type annotations
* [ ] Script to collect samples for all relevant commands on a platform
and save output into the appropriately named sub-directory in `samples/`.
* [ ] Vagrant images
    * [ ] Ubuntu
    * [ ] Fedora
    * [ ] FreeBSD
    * [ ] OpenBSD
    * [ ] Android (?)
    * [ ] Windows 7
    * [ ] Windows 10
