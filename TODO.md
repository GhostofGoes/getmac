
# Bugs or potential issues
* [X] Interface IP on Ubuntu gets loopback, instead of primary interface
* [ ] Unicode handling. UNICODE option needed for non-english locales? (Is LC_ALL working?)
* [ ] Are there ever cases where loopback != FF:FF:FF:FF:FF:FF?
* [ ] Remote host that is actually an interface should resolve to localhost MAC

# Features
* [X] make_arp_request
* [ ] Add ability to match user-provided arguments case-insensitively
* [ ] Add ability to get the mac address of a socket's interface
* [ ] Add support for Unix and Windows interface indices as a seperate
      argument to `get_mac_address`. On Windows, we could use `wmic`,
      while on Unix and Python 3 we can use `socket.if_indextoname()`.

## IPv6
* [ ] Support for IPv6 hostname resolution
    * [ ] Use `socket.getaddrinfo` instead of `socket.gethostbyname`
          to resolve a hostname to an IP address.

## Commands: Windows

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


## Non-Windows
* [ ] `arping`: investigate for remote macs
* [ ] `fcntl`: IPv6?


## Platforms
* [x] Linux
* [x] Windows (modern)
* [x] Darwin (Mac OS)
* [x] Windows Subsystem for Linux (WSL)
* [ ] OpenBSD
* [ ] FreeBSD
* [ ] Android (Which you could argue *correctly* is Linux)
* [ ] Solaris

## Other features
* [ ] Test against non-ethernet interfaces (WiFi, LTE, etc.)
* [ ] Threading (spin out all attempts, plus make itself thread-friendly)
* [ ] asyncio-friendly?

# Improvements
* [ ] Ignore case on regular expressions? (Better matching possibly)
* [ ] Cache results on regex-heavy functions (add a arg to disable this behavior)
* [ ] Ignore case on MAC regexs?
* [ ] Reduce the size on disk of the source code
* [ ] Improve performance (spend a lot of time on performance tuning with the regexes)

# Tests
* [ ] Unit tests for helper methods
* [ ] Mocked unit tests for core methods
* [ ] Run unit tests on all of the samples I've collected thus far
* [ ] Functional tests using Bats for all Python versions
* [x] Appveyor testing
* [ ] Unittesting of Python 2.6 (since we have it disabled on CLI tests)

# Documentation
* [ ] List of related works in README (shoutouts)
* [ ] List of 3rd-party packages that are attempted
* [ ] List of methods that are attempted
* [ ] Improve docuemntation on what it can and can't do
      (and educate the user on what MACs and broadcasts are)
* [ ] Sphinx documentation
* [ ] Man page
* [ ] HTML web documentation on ReadTheDocs
* [ ] Screenshots
* [ ] ASCII Cinema capture of usage
* [ ] Add documentation and other links to project_urls in setup.py
