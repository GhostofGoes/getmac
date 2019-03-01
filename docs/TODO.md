
# Etc
* Split `_hunt_for_mac()` into Remote and Interface
* Functions per-platform?
* Darwin hostnames? Does it have arp file? (Do less work)

# Bugs or potential issues
* [ ] Unicode handling. UNICODE option needed for non-english locales? (Is LC_ALL working?)
* [ ] Are there ever cases where loopback != FF:FF:FF:FF:FF:FF?
* [ ] Remote host that is actually an interface should resolve to localhost MAC
* [ ] Reduce the cost of failures. Currently, failures are penalized
with a slow run since it tries every method before failing.
* [ ] Detect if an interface exists before trying to find it's MAC.
* [ ] **Security**. Spend some quality time ensuring our sources of
input (the arguments to `get_mac_address()`) don't result in unexpected
code execution. A lot of stuff is running system commands, so we should
focus the most effort on the Popen calls.

# Platform support

## Windows

### Remote hosts
* [ ] IPv6: `netsh int ipv6 show neigh`
* [ ] IPv4: `netsh int ipv4 show neigh`
* [ ] `arping`


### Interface MACs
* [ ] `netsh int ipv6`
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


## POSIX
* [ ] `arping` (command): investigate for remote macs
* [ ] `fcntl` (library): IPv6?
* [ ] `ip addr` (command)


## OSX (Darwin)
* [ ] Determine best remote host detection methods, split off not-applicable commands


## Platform support
* [x] Linux
* [x] Windows (modern)
* [x] Darwin (Mac OS)
* [x] Windows Subsystem for Linux (WSL)
* [x] Docker (inside Docker containers)
* [x] Alpine Linux (test + add to tests)
* [ ] Raspberry Pi (test)
* [ ] FreeBSD
* [ ] OpenBSD
* [ ] Android
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
* [x] Use logging instead of print statements for debugging
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
* [x] Mocked unit tests for core methods
* [ ] Run unit tests on all of the samples I've collected thus far
* [ ] Need samples from many more platforms to build effective tests
* [x] Add MyPy checking to required tests
* [ ] Add profiling to tests. If average of multiple runs goes
 above a certain threshold, the tests fail.
* [ ] Get coverage reports fully working
* [ ] Get Coveralls working


# Documentation
* [ ] Sphinx documentation
* [ ] Host documentation on ReadTheDocs
* [ ] Add ReadTheDocs and other links to project_urls in setup.py


# Code/Other
* [ ] Add typing stubs to [typeshed](https://github.com/python/typeshed)
once getmac 1.0.0 is released ([guide](https://github.com/python/typeshed/blob/master/CONTRIBUTING.md))
* [ ] Create a script to collect samples for all relevant commands on a platform
and save output into the appropriately named sub-directory in `samples/`.
* [ ] Vagrant images
    * [ ] Fedora
    * [x] FreeBSD
    * [x] OpenBSD
    * [ ] Android (?)
    * [ ] Windows 7
    * [ ] Windows 10
