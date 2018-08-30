
# Bugs or potential issues
* [X] Interface IP on Ubuntu gets loopback, instead of primary interface
* [ ] Unicode handling. UNICODE option needed for non-english locales? (Is LC_ALL working?)

# Features
* [X] make_arp_request
* [ ] Add ability to match user-provided arguments case-insensitively
* [ ] Add ability to get the mac address of a socket's interface


## IPv6
* [ ] Support for IPv6 hostname resolution
    * [ ] Use `socket.getaddrinfo` instead of `socket.gethostbyname`
          to resolve a hostname to an IP address.

## Commands: Windows
### Remote hosts
* [ ] `getmac.exe`
* [ ] `netsh int ipv6 show neigh`
* [ ] `arping`
* [ ] Windows API

### Interface MACs
* [ ] `getmac.exe`
* [ ] `netsh int ipv6`
* [ ] `ipconfig`
* [ ] Windows API

### Default Interfaces
* [ ] `ipconfig`
* [ ] `route print -4`
* [ ] Windows API

## Commands: not-Windows
* [ ] `arping`: investigate for remote macs


## Platform TODO
* [x] Linux
* [x] Windows (modern)
* [ ] Windows (pre-2000)
* [x] Darwin (Mac OS)
* [ ] OpenBSD
* [ ] FreeBSD
* [ ] Android (Which you could argue [correctly] is Linux)
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
* [ ] Appveyor testing

# Documentation
* [ ] Sphinx documentation
* [ ] Man page
* [ ] HTML web documentation on ReadTheDocs
* [ ] Screenshots
* [ ] ASCII Cinema capture of usage


# Misc
* [ ] Support everything on this [list](https://www.python.org/dev/peps/pep-0011/#no-longer-supported-platforms).
That is partially in jest, partially insane[ity].
* [ ] Unittesting of Python 2.6 (since we have it disabled on CLI tests)
* [ ] Use optparse instead of argparse?
