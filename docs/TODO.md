

# 1.0.0 release
* Move method classes into a separate file
* Split utils into a separate file
* move more logic out of get_mac_address into individual methods
  interface
  remote host
  return data cleanup and validation
* Add docstrings to all util methods
* API to add/remove methods at runtime (including new, custom methods)
* Write a short guide on how to add and test a new method
* Parameterize regexes? (is this any faster?)
* Raise exceptions on critical failures during cache initialization
  such as a lack of valid methods or all tests failing can raise exceptions
  also make sure to document in `get_mac_address`
  (this is a major API change defer this change to 1.0.0?)
* Remove all Python "Scripts" from the path? Document this!
* Document possible values for `PLATFORM` variable
  Use `__import__()` or `importlib`?
* Document Method (and subclass) attributes (use Sphinx "#:" comments)
* Proper documentation (ReadTheDocs and Sphinx fanciness)
* Support IPv6 hosts: https://www.practicalcodeuse.com/how-to-arp-a-in-ipv6
* cleanup most or all of the TODOs
* >90% test coverage
  * refactor tests to use the new system and structure
  * directly test methods via a `Method.parse()` function
  * add `Method.parse()` that handles the parsing of command output.
      this would make it *much* easier to test methods
* implement proper default interface detection on Windows
* update the samples used in tests
* Reduce duplication, for example "if not arg: return None"

## Py3-related
* Drop support for python 2.7, 3.4, and 3.5
* support python 3.9 and 3.10 (add tests+setup.py classifier)
* BUMP TEST DEPENDENCIES AND PYTEST VERSION TO MODERN TIMES
* Use Enums for platforms and method types instead of strings?
* cache package imports done during test for use during `get()`, reuse
* rewrite strings to f-strings
* move from setup.py to setup.cfg and/or pyproject.toml
* update classifiers in setup.py

## Documentation
* [ ]


# Etc
* [ ] Refactor the default interface code. Combine the functions into 
one, move the default fallback logic into the function.

# Bugs or potential issues
* [ ] Fix lookup of a IPv4 address of a local interface on Linux
* [ ] Unicode handling. UNICODE option needed for non-english locales? (Is LC_ALL working?)
* [ ] Are there ever cases where loopback != `FF:FF:FF:FF:FF:FF`?
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

### Interface MACs
* [ ] `netsh int ipv6`
* [ ] win32 API (`ctypes`)

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
* [ ] Determine best remote host detection methods, 
      split off not-applicable commands.
* [ ] Darwin hostnames? Does it have arp file? (Do less work)


## Performance
* [ ] Profiling: CPU usage, memory usage, run time/load time

## Misc.
* [ ] Add ability to match user-provided arguments case-insensitively
* [ ] Add ability to get the mac address of a socket's interface
* [ ] Add support for Unix and Windows interface indices as a separate
      argument to `get_mac_address`. On Windows, we could use `wmic`,
      while on Unix and Python 3 we can use `socket.if_indextoname()`.
* [ ] Test against non-ethernet interfaces (WiFi, LTE, etc.)
* [ ] Threading (spin out attempts, make thread-friendly)
* [ ] asyncio-friendly?


# Code/Other
* [ ] Add typing stubs to [typeshed](https://github.com/python/typeshed)
once getmac 1.0.0 is released ([guide](https://github.com/python/typeshed/blob/master/CONTRIBUTING.md))
* [ ] Create a script to collect samples for all relevant commands on a platform
and save output into the appropriately named sub-directory in `samples/`.
* [ ] Move to GitHub Actions for automated testing instead of Appveyor/TravisCI
    * [ ] Automatically publish to PyPI when publishing a release on github
