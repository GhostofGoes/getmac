# Changelog

**NOTE**: if any changes significantly impact your project or use case, please open an issue on [GitHub](https://github.com/GhostofGoes/getmac/issues) or email me (see git commit author info for address).

**Announcement**: Compatibility with Python versions older than 3.7 (2.7, 3.4, 3.5, and 3.6) is deprecated and will be removed in getmac 1.0.0. If you are stuck on an unsupported Python, consider loosely pinning the version of this package in your dependency list, e.g. `getmac<1.0.0` or `getmac~=0.9.0`.

## 0.9.4 (06/01/2023)

### Added
* Support BusyBox's ``arping``

### Changed
* Improve how ARP is handled. If ``ArpFile`` method succeeds, use it instead of ``ArpingHost`` (this should fix [#86](https://github.com/GhostofGoes/getmac/issues/86), for realsies this time).
* Speed up the first call to ``ArpingHost``
* Fix FORCE_METHOD not being respected for IPv4 macs

## 0.9.3 (03/16/2023)

### Changed
* Fix `ArpFile` method being used for IPv6 (`/proc/net/arp`, and ARP in general, is IPv4-only)

## 0.9.2 (02/03/2023)

### Changed
* Fix flakiness with UuidArpGetNode on MacOS by making it the last method attempted (Fixes issue [#82](https://github.com/GhostofGoes/getmac/issues/82))

## 0.9.1 (01/24/2023)

### Changed
* Deprecate Python 3.6 support (support will be removed in getmac 1.0.0)

### Dev
* Fix links in README and PyPI metadata to use "main" instead of "master" for primary branch
* Remove "Documentation" link from PyPI (the ReadTheDocs site is broken and hasn't been updated since 0.5.0)
* Add PyPI classifiers for 3.10 and 3.11
* Some cleanup of CHANGELOG


## 0.9.0 (01/23/2023)
This release is a *complete rewrite of getmac from the ground up*. The public API of `getmac` is **unchanged** as part of this rewrite. `get_mac_address()` is still the primary way of getting a MAC address, it's just the "under the hood" internals that have changed completely.

 It's passing tests and seems to be operable. However, with a change this large there are inevitably issues that the tests or I don't catch, so I'm doing a series of pre-releases until I'm 99% confident in it's stability. Refer to `docs/rewrite.md` for a in-depth explanation of the rewrite changes.

The new system has a number of benefits
- Reduction of false-positives and false-negatives by improving method selection accuracy (platform, validity, etc.)
- *Significantly* faster overall
- "Misses" have the same performance as "Hits"
- Easier to test, since each method can be tested directly via it's class
- Easier to type annotate and analyze with mypy
- Easier to read, improving reviewability and ease of contributing for newcomers
- Extensible! Custom methods can be defined and added at runtime (which is perfect if you have some particular edge case but aren't able to open-source it).

### Added
* Fully support Python 3.9 (automated tests in CI)
* Tentatively support Python 3.10 and 3.11 (unable to test due to the need to be able to still test 2.7)
* Added default interface detection for MacOS (command: `route get default`)
* Added initial support for Solaris/SunOS. There were a few existing methods that worked as-is, so just added indicators that those methods support `sunos` (Which applies to any system where `platform.system() == SunOS`).
* `arping` (POSIX) or `SendARP` (Windows) will now *always* be used instead of sending a UDP packet when looking for the MAC of a IPv4 host, if they're available and operable (otherwise, UDP + ARP table check will be used like before).
* The amount of time taken to get a result (in seconds) will now be recorded and logged if debugging is enabled (`DEBUG>=1` or `-d`)
* Added command line argument to override the UDP port for network requests: `--override-port` (this was already possible in Python via `getmac.getmac.PORT`, but wasn't configurable via the CLI. Now it is!).
* Added ability to override the detected platform via `--override-platform` argument (CLI) or `getmac.getmac.OVERRIDE_PLATFORM` variable (Python). This will force methods for that platform to be used, regardless of the actual platform. Here's an example forcing `linux` to be used as the platform: `getmac -i eth0 --override-platform linux`. In version 1.0.0, this feature will added as an argument to `get_mac_address()`.
* Added ability to force a specific method to be used via `--force-method` argument (CLI) or `getmac.getmac.FORCE_METHOD` variable (Python). This is useful for troubleshooting issues, general debugging, and testing changes. Example: `getmac -v -dddd --ip 192.168.0.1 --force-method ctypeshost`

### Changed
* **Complete rewrite of `getmac` from the ground up. Refer to `docs/rewrite.md` for a in-depth explanation of the rewrite changes**
* Fixed a failure to look up a hostname now returns `None`, as expected, instead of raising an exception (`socket.gaierror`).
* Fixed numerous false-negative and false-positive bugs
* Improved overall performance
* Performance for cases where no MAC is found is now the same as cases where a MAC is found (speed of "misses" now equals that of "hits")
* Improved the reliability and performance of many methods
* Fixed `netstat` on older Linux distros (such as Ubuntu 12.04)
* Overhauled `ifconfig` parsing. It should now be far more reliable and accurate across all platforms.
* Improved Android support. Note that newer devices are locked down and the amount of information that's obtainable by an unprivileged process is quite limited (Android 7/9 and newer, not sure exactly when they changed this, I'm not an Android guy). That being said, the normal Linux methods should work fine, provided you have the proper permissions (usually, `root`).
* Fixed bug with `/proc/net/route` parsing (this affected Android and potentially other platforms)
* Improve default interface detection for FreeBSD (command: `route get default`)

### Removed
* Removed man pages from distribution (`getmac.1`/`getmac2.1`). They were severely out of date and unused. May re-add at a later date.

### Dev
* Migrate CI to GitHub Actions, remove TravisCI and Appveyor
* Add flake8 plugins: `flake8-pytest-style` and `flake8-annotations`
* Add additional samples and tests for WSL1 (with the Ubuntu 18.04 distro)
* Add additional samples for Windows 10
* Add additional samples for MacOS
* Add samples and tests for Ubuntu 12.04
* Add samples for NetBSD 8 (support coming in a future release)
* Add samples for Solaris 10 (support TBD)
* Add samples for several versions of Android
* Add new tests
* Improve existing tests
* Consolidate everything related to RPM packaging to `packaging/rpm/`. This stuff hasn't been updated since 0.6.0, may remove in the future and leave distro packaging to distro maintainers.


## 0.8.3 (12/10/2021)

### Changed
* Added support for Thomas Habets' version of `arping` in addition to the existing iputils one (contributed by Ville Skyttä (@scop) in [#52](https://github.com/GhostofGoes/getmac/pull/52) and [#54](https://github.com/GhostofGoes/getmac/pull/54))
* Added support for docker in network bridge mode (contributed by Tomasz Duda (@tomaszduda23) in [#57](https://github.com/GhostofGoes/getmac/pull/57))
* Add CHANGELOG URL to PyPI metadata (contributed by Ville Skyttä (@scop) in [#58](https://github.com/GhostofGoes/getmac/pull/58))
* Fixed code quality test suite errors (includes changes by Daniel Flanagan (@FlantasticDan) in [#67](https://github.com/GhostofGoes/getmac/pull/67))
* Improved Android support (contributed by @emadmahdi in [#71](https://github.com/GhostofGoes/getmac/pull/71))
* Minor code quality fixes (2 years of neglecting master branch)
* Add [Code of Conduct](https://github.com/GhostofGoes/getmac/blob/main/CODE_OF_CONDUCT.md) for project contributors
* Add [SECURITY.md](https://github.com/GhostofGoes/getmac/blob/main/SECURITY.md) for reporting security issues (e.g. vulnerabilities)
* Deprecate Python 3.4 and 3.5
* Issue deprecation message as a warning in addition to a log message


## 0.8.2 (12/07/2019)

### Changed
* Added warning about Python 2 compatibility being dropped in 1.0.0
* Officially support Python 3.8
* Documented a known issue with looking up IP of a local interface on Linux/WSL (See the "Known Issues" section in the README)
* Added remote host lookup using `arping` as last resort

### Dev
* Standardized formatting on [Black](https://github.com/psf/black)
* Lint additions: `vulture`, several Flake8 plugins
* Pinned test dependencies (pytest 5 dropped Python 2 support)
* Various quality-of-life improvements for contributors/developers


## 0.8.1 (05/14/2019)

### Changed
* Fixed sockets being opened and not closed when `ip` or `ip6` were used,
which could lead to a `ResourceWarning` (GH-42)


## 0.8.0 (04/09/2019)

### Added
* OpenBSD support
* FreeBSD support
* Python logging is now used instead of `print` (logger: `getmac`)
* Include tests in the source distribution
* (CLI) Added aliases for `--no-network-requests`: `-N` and `--no-net`
* (CLI) New argument: `-v`/`--verbose`

### Changed
* Errors are now logged instead of raising a `RuntimeWarning`
* Improved Ubuntu support
* Performance improvements

### Development
* Significant increase in overall test coverage
* Fixed and migrated the sample tests to `pytest`
* Added tests for the CLI


## 0.7.0 (01/27/2019)

### Added
* Type annotations (PEP 484)

### Removed
* Dropped support for Python 2.6
* Removed the usage of third-party packages (`netifaces`, `psutil`, `scapy`, and `arpreq`).
This should improve the performance of lookups of non-existent interfaces
or hosts, since this feature was punishing that path without providing much value.
If you want to use these packages directly, I have a guide on how to do so on a
[GitHub Gist](https://gist.github.com/GhostofGoes/0a8e82930e75afcefbd879a825ba4c26).

### Changed
* Significantly improved the performance of the common cases on Linux
for interfaces and remote hosts
* Improved POSIX interface performance. Commands specific to OSX
will be run only on that platform, and vice-versa.
* Significantly improved the speed and accuracy of determining
the default interface on Linux
* Python 2 will install an executor named getmac2 and Python 3 an
executor named getmac so they do not conflict when both RPMs are
installed on the same system (Credit: @hargoniX)
* The `warnings` module will only be imported if a error/warning
occurs (improve compatibility with some freezers, notably PyInstaller)
* Improved system platform detection
* Various other minor performance improvements

### Development
* Added unit tests for the samples (Credit: @Frizz925)
* Scripts for building RPMs in the /scripts directory (Credit: @hargoniX)
* Improved code quality and health checks
* Include the CHANGELOG on the PyPI project page
* Using `pytest` for all tests now instead of `unittest`

### Documentation
* Added instructions on how to build a Debian package (Credit: @kofrezo)


## 0.6.0 (10/06/2018)
### Added
* Windows default interface detection if `network_request` is enabled (Credit: @cyberhobbes)
* Docker container (Credit: @Komish)

### Changed
* Changed project name to `getmac`. This applies to the
command line tool, GitHub, and the documentation.
* Use proper Python 2-compatible print functions (Credit: @martmists)

### Removed
* Support for Python 2.5. It is not feasible to test, and potentially
breaks some useful language features, such as `__future__`
* Variables PORT and DEBUG from top-level package imports, since changing
them would have no actual effect on execution. Instead, use `getmac.getmac.DEBUG`.

### Dev
* Added example videos demonstrating usage (Credit: @fortunate-man)
* Added contribution guide
* Added documentation on ReadTheDocs
* Added a manpage


## 0.5.0 (09/24/2018)
### Added
* Full support for Windows Subsystem for Linux (WSL). This is working for
all features, including default interface selection! The only edge case
is lookup of remote host IP addresses that are actually local interfaces
will not resolve to a MAC (which should be ff-ff-ff-ff-ff-ff).
### Changed
* Require `argparse` if Python version is 2.6 or older
### Dev
* Updated tox tests: added Jython and IronPython, removed 2.6


## 0.4.0 (09/21/2018)
### Added
* New methods for remote host MACs
    * Windows: `arp`
    * POSIX: `arpreq` package
* New methods for interface MACs
    * Windows: `wmic nic`
* DEBUG levels: DEBUG value is now an integer, and increasing it will
increase the amount and verbosity of output. On the CLI, it can be
configured by increasing the amount of characters for the debug argument,
e.g. '-dd' for DEBUG level 2.
* Jython support (Note: on Windows Jython currently only works with interfaces)
* IronPython support

### Changed
* **Significant** performance improvement for remote hosts. Previously,
the average for `get_mac_address(ip='10.0.0.100')` was 1.71 seconds.
Now, the average is `12.7 miliseconds`, with the special case of a unpopulated
arp table being only slightly higher. This was brought about by changes in
how the arp table is populated. The original method was to use the
host's `ping` command to send an ICMP packet to the host. This took time,
which heavily delayed the ability to actually get an address. The solution
is to instead simply send a empty UDP packet to a high port. The port
this packet is sent to can be configured using the module variable `getmac.PORT`.
* "Fixed" resolution of localhost/127.0.0.1 by hardcoding the response.
This should resolve a lot of problematic edge cases. I'm ok with this
for now since I don't know of a case when it isn't all zeroes.
* Greatly increased the reliability of getting host and interface MACs on Windows
* Improved debugging output
* Tightened up the size of `getmac.py`
* Various minor stability and performance improvements
* Add LICENSE to PyPI package

### Removed
* Support for Python 3.2 and 3.3. The total downloads from PyPI with
those versions in August was ~53k and ~407K, respectfully. The majority
of those are likely from automated testing (e.g. TravisCI) and not
actual users. Therefore, I've decided to drop support to simplify
development, especially since before 3.4 the 3.x series was still
very much a  "work in progress".

### Dev
* Added automated tests for Windows using Appveyor
* Tox runner for tests
* Added github.io page
* Improved TravisCI testing


## 0.3.0 (08/30/2018)
### Added
* Attempt to use Python modules if they're installed. This is useful
for larger projects that already have them installed as dependencies,
as they provide a more reliable means of getting information.
    * `psutil`: Interface MACs on all platforms
    * `scapy`: Interface MACs and Remote MACs on all platforms
    * `netifaces`: Interface MACs on Non-Windows platforms
* New methods for remote MACs
    * POSIX: `ip neighbor show`, Abuse of `uuid._arp_getnode()`
* New methods for Interface MACs
    * POSIX: `lanscan -ai` (HP-UX)

### Changed
* Certain critical failures that should never happen will now warn
instead of failing silently.
* Added a sanity check to the `ip6` argument (IPv6 addresses)
* Improved performance in some areas
* Improved debugging output

### Fixed
* Major Bugfix: search of `proc/net/arp` would return shorter addresses in the
same subnet if they came earlier in the sequence. Example: a search for
`192.168.16.2` on Linux would instead return the MAC address of
`192.168.16.254` with no errors or warning whatsoever.
* Significantly improved default interface detection. Default
interfaces are now properly detected on Linux and most other
POSIX platforms with `ip` or `route` commands available, or the
`netifaces` Python module.

### Dev
* Makefile
* Vagrantfile to spin up testing VMs for various platforms using [Vagrant](https://www.vagrantup.com/docs/)
* Added more samples of command output on platforms (Ubuntu 18.04 LTS)


## 0.2.4 (08/26/2018)
### Fixed
* Fixed identification of remote host on OSX
* Resolved hangs and noticeable lag that occurred when "network_request"
was True (the default)


## 0.2.3 (08/07/2018)
### Fixed
* Remote host for Python 3 on Windows


## 0.2.2
### Added
* Short versions of CLI arguments (e.g. "-i" for "--interface")

### Changed
* Improved usage of "ping" across platforms and IP versions
* Various minor tweaks for performance
* Improved Windows detection

### Fixed
* Use of ping command with hostname

### Dev:
* Improvements to internal code


## 0.2.1
Nothing changed. PyPI just won't let me push changes without a new version.


## 0.2.0 (04/15/2018)
### Added
* Checks for default interface on Linux systems
* New methods of hunting for addresses on Windows, Mac OS X, and Linux

### Changed
* CLI will output nothing if it failed, instead of "None"
* CLI will return with 1 on failure, 0 on success
* No CLI arguments now implies the default host network interface
* Added an argumnent for debugging: `--debug`
* Removed `-d` option from `--no-network-requests`

### Fixed
* Interfaces on Windows and Linux (including Bash for Windows)
* Many bugs

### Removed
* Support for Python 2.6 on the CLI

### Dev
* Overhaul of internals


## 0.1.0 (04/15/2018):
### Added
* Addition of a terminal command: `get-mac`
* Ability to run as a module from the command line: `python -m getmac`

### Changed
* `arp_request` argument was renamed to `network_request`
* Updated docstring
* Slight reduction in the size of getmac.py

### Dev
* Overhauled the README
* Moved tests into their own folder
* Added Python 3.7 to list of supported snakes


## 0.0.4 (11/12/2017):
* Python 2.6 compatibility


## 0.0.3 (11/11/2017):
* Fixed some addresses returning without colons
* Added more rigorous checks on addresses before returning them


## 0.0.2 (11/11/2017):
* Remove print statements and other debugging output


## 0.0.1 (10/23/2017):
* Initial pre-alpha
