
# 1.0.0 release

## Before releasing
- [ ] After the first Docker image is published, make the GHCR package public


# Etc
- [ ] cache the result of executable checks in `getmac.utils.popen()`
- TODO: MAC -> IP. "to_find='mac'"? (create GitHub issue?)


# Bugs or potential issues
- [ ] Fix lookup of a IPv4 address of a local interface on Linux
- [ ] Unicode handling on non-English systems. `LC_ALL=C` works on POSIX (it stops net-tools from translating its output) and no "UNICODE" regex option is needed, but on Windows:
    - [x] `utils.call_proc()` decoded output as strict UTF-8, while Windows commands print in the OEM code page (e.g. cp850, cp866). It now decodes with UTF-8, then the `oem` codec with `errors="replace"`.
    - [x] `IpconfigExe` needed the English "Physical Address" label. It now matches the MAC value (the only 6-byte value in an adapter's section), and its regex no longer backtracks catastrophically.
    - [ ] `IpconfigExe` only finds adapter names in English output, since the headers are translated (e.g. `Ethernet adapter Ethernet 3:` is `Carte Ethernet Ethernet 3 :` in French and `Ethernet-Adapter Ethernet 3:` in German). The name is always last, so match headers that end with ` <name>`, preferring the exact English `adapter <name>` match. Watch for names that end another adapter's name (`Ethernet` and `Realtek Ethernet`). Descriptions aren't translated, but the "Description" label is (e.g. `Beschreibung` in German).
    - `WmicExe` is the last working fallback, and WMIC is being removed from Windows 11.
    - [ ] Collect real samples from non-English Windows systems (e.g. French, German, Spanish, Japanese) with `scripts/collect_samples.py`, especially `ipconfig.exe /all`, and use them to test the methods. The only non-English Windows samples so far are French `arp -a` output from glpi-agent (`tests/samples/third_party/glpi_agent/generic/arp/`).
- [ ] Loopback lookups. On Linux `lo` is `00:00:00:00:00:00` (root can change it); on macOS, BSDs, Solaris, HP-UX and Windows the loopback interface has no MAC, so `00:00:00:00:00:00` is a getmac convention there.
    - The `localhost`/`127.0.0.1` shortcut only matches those exact strings. `LOCALHOST`, `127.0.0.2`, `::1` and the host's own name (`127.0.1.1` on Debian) return `None` and send a UDP packet to the host itself. Check `ipaddress.ip_address(...).is_loopback` after resolving instead.
    - Methods disagree on `lo`: `SysIfaceFile` and `FcntlIface` return the zero MAC, `IpLinkIface` and the `ifconfig` parsers return `None`.
- [ ] Exceptions from a method forced with `FORCE_METHOD` aren't caught, which contradicts the `get_mac_address()` docstring and `docs/usage.rst`.
- [ ] Docstrings that don't match the code: `get_default_interface()` can raise `RuntimeError`, `get_instance_from_cache()` returns an instance (not a class), `utils.search()` uses `groups()` (not `groupdict()`), `get_method_by_name()` has no docstring, and `Method.get()` returns raw output (not a cleaned MAC).
- [ ] Remote host that is actually an interface should resolve to localhost MAC
- [ ] Reduce the cost of failures. Currently, failures are penalized
with a slow run since it tries every method before failing.
- [ ] Detect if an interface exists before trying to find it's MAC.
- [ ] **Security**. Spend some quality time ensuring our sources of input (the arguments to `get_mac_address()`) don't result in unexpected code execution. A lot of stuff is running system commands, so we should focus the most effort on the `subprocess.Popen()` calls.


# API Features
- [ ] [issue 77](https://github.com/GhostofGoes/getmac/issues/77): Feature: get all mac addresses
    - "As I was thinking of adding support to jaraco.net for supporting macOS devices (IP addresses and mac addresses), I thought getmac might be a helpful solution, but as I delved into it, I could see that getmac only returns a single mac, even though there may be multiple on a host. It would be nice if getmac could abstract some of its behaviors, mainly to allow a user to query for all mac addresses represented by the host."
- [ ] Add support for Unix and Windows interface indices as a separate argument to `get_mac_address`. On Windows, we could use `wmic`, while on Unix and Python 3 we can use `socket.if_indextoname()`.
- [ ] Add ability to match user-provided arguments case-insensitively
- [ ] Add ability to get the mac address of a Python socket's interface (`socket.socket`)
- [ ] API to add/remove methods at runtime (including new, custom methods)
    - [x] Document this API and how the method API functions work more generally (`docs/module_api.rst`)

# Platform support

### Remote hosts
do this next, i guess, to get ipv6 working on windows + WSL
also, on WSL, do netsh.exe instead of netsh
https://web.archive.org/web/20220814083605/https://www.prodjim.com/how-to-arp-a-in-ipv6

- [x] IPv6: `netsh int ipv6 show neigh`
- [x] IPv4: `netsh int ipv4 show neigh`

### Interface MACs
- [ ] New method for PowerShell's `Get-NetAdapter` (e.g. `powershell.exe -NoProfile -NonInteractive -Command "Get-NetAdapter | Format-List -Property Name,InterfaceDescription,MacAddress"`). Its property names and values aren't translated, and it replaces WMIC, which is being removed from Windows 11 (`WmicExe`). PowerShell is slow to start (about 0.3 to 1 seconds), so it should come after `GetmacExe` and `IpconfigExe` in `METHODS`. `scripts/collect_samples.py` already collects its output (`powershell_Get-NetAdapter.out`), but there aren't any samples of it yet.
- [ ] `netsh int ipv6`
- [ ] win32 API (`ctypes`)

### Default Interfaces
This is going to be a bit more complicated since the highest metric routes are going to be IP addresses and not interfaces. We'll have to resolve those to an interface, then select that interface as the default route.
- [x] IPv4: `netsh interface ipv4 show route`
- [ ] IPv6: `netsh interface ipv6 show route`
- [ ] `ipconfig`
- [ ] IPv4: `route print -4`
- [ ] IPv6: `route print -6`
- [ ] Windows API

## POSIX
- [ ] `arping` (command): investigate for remote macs
- [ ] `fcntl` (library): IPv6?
- [ ] `ip addr` (command)
- [ ] `ip -6 neigh` (command)

## OSX (Darwin)
- [ ] Determine best remote host detection methods, split off not-applicable commands.
- [ ] Darwin hostnames? Does it have arp file? (Do less work)
- [ ] Mac: `ndp -a` to get IPv6 network neighbors (NDP table)

## Misc platforms
- [ ] Properly support WSL2
- [ ] `nwmgr` for HP-UX
- [ ] Properly implement and test HP-UX for `netstat` and `ifconfig`, add `hp-ux` to `platforms` for corresponding Methods
- [ ] FreeBSD default interface: `route get default`
- [ ] Support NetBSD
    - platform: `netbsd`
    - default interface: `wm0`
    - ip: "route -nq show", "netstat -r", arp -a
    - default interface via `route get default`?
- [ ] Support Solaris
    - platform: `sunos`
    - default interface; `e1000g0` (NOTE: likely because this is in Vagrant VM)
    - `ifconfig` with no arguments DOES NOT work, need `ifconfig -a`
    - `netstat` doesn't work with `-e`, but does work with no arguments, `-a` and `-i`. `-n` prevents hostnames from resolving, which is faster. `-i` gives the shortest output (and is fastest), but doesn't give us a MAC address. Providing the interface as an argument also doesn't work to get a MAC (`netstat -a -I e1000g0`).
    - default interface via `route get default`?
    - no `ip` command


# Performance
- [ ] Profiling: CPU usage, memory usage, run time/load time
- [ ] Parameterize regexes? (is this any faster?)
- [ ] Cache method checks (maybe move this to 1.1.0 release?) Save a string with the names of methods. Save to: file (location configurable via environment variable or option). Read from: file, environment variable, file pointed to by environment variable. Add a flag to control this behavior and location of the cache. Document the behavior.
- [ ] Refactor to build a local state of the interfaces on the system, and use that as fallback for default lookup of interface with no name. Could also include MACs for faster lookup of future interface queries. Similar to how `netifaces` works, with a dict with interface infos. Properly address https://github.com/GhostofGoes/getmac/issues/78


# Testing
- [ ] Test against non-ethernet interfaces (WiFi, LTE, etc.)


# Dev
- [ ] OpenSSF best practices badge
- [ ] Add typing stubs to [typeshed](https://github.com/python/typeshed) once getmac 1.0.0 is released ([guide](https://github.com/python/typeshed/blob/master/CONTRIBUTING.md))
- [ ] Add to Conda Forge ([example here](https://github.com/conda-forge/staged-recipes/pull/26828/files))
- [ ] Move method classes into a separate file
- [ ] Generate a GitHub release in GitHub Actions when a version tag is pushed (publishing to PyPI is already automated).
    - This is going to require re-doing how changelogs are created a bit.
- [ ] Use towncrier for release notes (or another fragment-file based system, avoid merge conflicts)
- [ ] Use `prek` for linting


# Post-1.0.0
- [ ] Cleanup `ifconfig` methods
  - [ ] Split `IfconfigOther` into IfconfigWithArg/IfconfigNoArg
  - [ ] Combine `IfconfigEther` into other Ifconfig methods
  - [ ] Improve unit test coverage and platform markers
- [ ] `IpLinkIface`: improve regex to not need extra portion for no arg
- [ ] Add new regexes to `IpLinkIface` and improve it's parsing so it's more robust, especially on Android
- [ ] finer-grained platform support identification for methods by versions/releases, e.g. Windows 7 vs 10, Ubuntu 12 vs 20
- [ ] address all TODOs in the code
- [ ] Support IPv6 hosts: https://web.archive.org/web/20210730102525/https://www.practicalcodeuse.com/how-to-arp-a-in-ipv6
- [ ] Support IPv4+IPv6 remote hosts on WSL (see "Platform support" section in this document)
- [ ] New method for "ip addr"? (this would be useful for CentOS and others as a fallback)
- [ ] Method-specific loggers? dynamically set logger name based on subclass name, so we don't have to manually set it in the string
- [ ] Use `__import__()` or `importlib`?
- [ ] Reduce duplication, for example "if not arg: return None"

## Breaking changes (or potentially breaking)
- [ ] **Consolidate `ip6` argument into `ip` argument.**. Parse based on `::` character vs `.` character if `str` or via `.version == 4`/`.version == 6` for `ipaddress` objects.
    - Combine `--ip` and `--ip6` CLI arguments into `--ip` output. this would make it *much* easier to test methods.
    - keep `-4,`, `-6`, and `--ip6` arguments for backwards-compatibility until 1.1.0
- [ ] **API changes** (technically speaking)
    - Add argument to `get_mac_address()` to force the platform used (e.g. `platform_override="linux"`)
        - Also add CLI argument to configure this
    - Add argument to `get_mac_address()` to force a specific method(s) to be used
        - Passing a string with the name of a method class (e.g. `"ArpFile"`), this will be dynamically looked up from the list of available methods. This will NOT check if the method works by default!
        - Passing a subclass of `getmac.Method`
        - Passing an instance of a subclass of `getmac.Method`
        - List/Iterable of methods (as above, string/subclass/instance)
        - Add a CLI argument to reference class by name/names
    - Add ability to exclude methods. Just remove them from METHODS list so they never get used. Useful for testing specific methods or working around buggy methods.
    - Document these features in the README/docs, including the CLI arguments

```
methods=None
type: Optional[List[Union[str, Method, Type[Method]]]]
methods (list): Optional list of methods to use for MAC address lookup.
            This will override the default methods that are auto-determined based on
            platform inspection and testing, and will be used regardless of whether
            they work or not. These can be names of method classes as strings
            (``"ArpFile"``), ``Method`` subclasses (``ArpFile``),
            or instances of ``Method`` subclasses (``ArpFile()``).
```


# Completed tasks

## 1.0.0 release

### Documentation
- [x] Single page on RTD/publish with GitHub actions built with Sphinx and Furo
- [x] Update docs/usage examples for `get_mac_address()`
- [x] Document possible values for `PLATFORM` variable
- [x] Document Method (and subclass) attributes (use Sphinx "#:" comments)
- [x] Re-add Man pages (and auto-build them in CI)
- [x] Document `get_by_method()`
- [x] Document `initialize_method_cache()`
- [x] Auto-generated API docs
- [x] Add docstrings to all util methods
- [x] Furo, sphinx-autodoc-typehints, sphinx-argparse-cli, sphinx-automodapi, sphinx-copybutton, recommonmark

### Tests
- [x] >90% test coverage
- [x] Improve CLI tests to ensure output is what's expected (e.g. ensure `--override-port` logs a warning and the value actually gets overridden)
- [x] Add tests for more samples (new third-party samples)
- [x] Add test to ensure only the expected files make it into the sdist and wheel, no unexpected files

### Features
- [x] Support `ipaddress` objects, `IPv4Address` and `IPv6Address`
- [x] Add new method: `get_default_interface()`. This leverages the default interface detection methods to expose a helpful public API.

### Breaking changes (or potentially breaking)
- [x] Replace the `UuidArpGetNode` method. It calls 3 commands and is quite inefficient. It's functionality is already implemented by `ArpVariousArgs`.
- [x] Raise exceptions on critical failures (stuff that were warnings in 0.9.0), all calls to `_warn_critical()`.

### Enhancements/fixes/misc.
- [x] Python 3.15 (pre-release) in CI
- [x] [issue #76](https://github.com/GhostofGoes/getmac/issues/76): get_mac_address() is caching an old mac address, no longer present in local ARP
  - get_mac_address() is caching an old mac address for a given IP, even when it has timeout from OS ARP table. Only an explicit delete of the ARP entry on the OS make it return '00:00:00:00:00:00' again.
  - Fixed by only using `/proc/net/arp` entries with the `ATF_COM` (completed, `0x2`) flag set, which ignores incomplete, failed (`0x0`) and proxy (`0xc`) entries.
- [x] Python 3.13 + 3.14
- [x] Fix `UuidLanscan` for Python 3.9+
- [x] [issue #78](https://github.com/GhostofGoes/getmac/issues/78): when the default interface can't be found (e.g. no routes) or has no MAC, use the first non-loopback interface with a MAC, or return `None` (instead of guessing `eth0` and falling back to `lo`). The fallback logic is in one function, `_default_interface_mac()`.
- [x] [issue #90](https://github.com/GhostofGoes/getmac/issues/90): Windows methods for IPv6 lookups (`NetshNeighbors`) and the default interface (`DefaultIfaceNetsh`), so Windows doesn't fall back to the "other" methods that run `arp.exe`/`route.exe` with Unix-style arguments. Windows interface names are matched exactly (`GetmacExe` uses CSV output).
- [x] [issue #95](https://github.com/GhostofGoes/getmac/issues/95): detect Python 3.13+ on Android as Linux, list the methods in the "failed to test" error, and document the Android limitations.
- [x] [issue #101](https://github.com/GhostofGoes/getmac/issues/101): `settings.ARP_TIMEOUT` (`--arp-timeout`) to wait for the host's ARP/NDP entry after the UDP packet (off by default).
- [x] `get_mac_address(network_request=False)` (and `-N`) now passes `network_request` on to `get_by_method()`, which skips methods that send packets (`ArpingHost`, `CtypesHost`) even if they're cached.
- [x] `FORCE_METHOD` and the IPv4 network request: the case-insensitive comparison with `"CtypesHost"`/`"ArpingHost"` now matches, so no UDP packet is sent when forcing them.
- [x] When `ArpFile` is a fallback and fails during the IPv4 ARP table check, it's removed from the fallbacks, instead of replacing the working primary method.

### Before releasing
- [x] Remove `1.0.0-wip` from the GitHub Pages deploy condition in `ci.yml` when merging into `main`
- [x] Add the 0.9.6 entry from `main`'s CHANGELOG to this branch's CHANGELOG
- [x] Update supported versions table in [SECURITY.md](../SECURITY.md)

### Done for 1.0.0
- [x] Move to PDM from Poetry
- [x] Split getmac.py into separate files for methods, utils, etc.
- [x] rename "master" branch to "main"
- [x] Create 0.9.0 branch from master/main so we can submit patch releases if needed
- [x] Drop support for python 2.7, 3.4, and 3.5
- [x] BUMP TEST DEPENDENCIES AND PYTEST VERSION TO MODERN TIMES (especially pytest...)
- [x] Use `pyproject.toml` instead of `setup.py`
- [x] update classifiers in setup.py
- [x] add inline type annotations for method arguments. remove types from docstrings?
- [x] Remove `shutilwhich.py` and `.coveragerc`
- [x] Replace `flake8-mypy` with proper execution of mypy in tests (the project is dead and archived, https://github.com/ambv/flake8-mypy)
- [x] Support Python 3.10 and 3.11
    - [x] Update pytest (pytest 4, which we were using to support python 2.7, doesn't work with python 3.10)
    - [x] add tests + setup.py classifier
- [x] Refactor how global variables are handled
- [x] rewrite strings to f-strings
- [x] CLI: put "override" and other debugging-related arguments into a separate argparse argument group
- [x] Remove all Python "Scripts" from the path, so they don't interfere with the commands we actually want (e.g. "ping").

## Documentation
- [x] Add guide on using the modules API, e.g. registering a new method in `getmac.getmac.METHODS`, etc. (`docs/module_api.rst`)
- [x] Write a short guide on how to add and test a new method (`docs/adding_methods.rst`)

## Dev
- [x] Publish releases to PyPI from GitHub Actions when a version tag is pushed (Trusted Publishing, with attestations on PyPI and GitHub)
- [x] Create a script to collect samples for all relevant commands on a platform and save output into the appropriately named sub-directory in `samples/`.
- [x] Add [isort](https://pycqa.github.io/isort/) (requires python 3.8+)
