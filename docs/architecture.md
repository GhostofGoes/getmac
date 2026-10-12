# Architecture

This page describes how getmac is put together: the pieces, how a lookup flows through them, and the design decisions behind it. It's for contributors and for anyone who wants to know what getmac does on their system before using it. The [module API](module_api.rst) and [adding methods](adding_methods.rst) pages have the details of the classes and functions mentioned here.

## Goals and constraints

getmac has one job: return the MAC address of a local network interface or of a host on the local network, on as many platforms as possible, with nothing to install. That leads to the constraints the design follows:

- **Pure Python, standard library only.** No runtime dependencies and no compiled extensions, so getmac can be vendored or installed anywhere Python runs (CPython and PyPy, 3.9 and newer).
- **Many platforms, one interface.** Windows, Linux, macOS, WSL, the BSDs, Solaris, HP-UX, Android, Docker, and BusyBox all have different commands and files for the same information. The caller never sees the difference.
- **No privileges needed.** Everything getmac does works as a normal user. Methods that need root (such as `arping`) are tried only when they're available, and skipped otherwise.
- **Fail quietly, by default.** A lookup that can't find a MAC returns `None` and logs why. getmac only raises when something is wrong with how it was called, or when no method at all works on the platform.

## The pieces

| Module | What it holds |
|---|---|
| `getmac/getmac.py` | The `Method` base class, every platform-specific method, the `METHODS` registry, the method selection and fallback machinery, and the public functions `get_mac_address()` and `get_default_interface()`. |
| `getmac/variables.py` | All module-level state, in three singletons: `settings` (what users may change), `consts` (platform detection results, fixed at import), and `gvars` (other mutable state: the search `PATH`, the subprocess environment, the logger, caches). |
| `getmac/utils.py` | Standalone helpers: checking that a command exists, reading a file, running a command (`popen()` and `call_proc()`), searching output with a regular expression, and normalising a MAC address string (`clean_mac()`). |
| `getmac/__main__.py` | The command line interface, a thin `argparse` wrapper around `get_mac_address()`. |
| `getmac/__init__.py` | The public exports. |

Everything a user calls is in `getmac.get_mac_address()`, `getmac.get_default_interface()`, and `getmac.settings`.

## How a lookup works

1. **Normalise the arguments.** `get_mac_address()` accepts one of `interface`, `ip`, `ip6`, or `hostname`. `bytes` are decoded as UTF-8, `ipaddress` objects are converted to strings (an IPv6 object passed as `ip` is treated as `ip6`), and IP address strings must parse as an address of the right family. `localhost` and `127.0.0.1` return `00:00:00:00:00:00` without doing anything else. A hostname is resolved to an IPv4 address with the system resolver.
2. **Refresh the ARP/NDP table, if asked.** Operating systems only know the MAC of a host they've talked to recently. For a remote host, when `network_request` is true (the default), getmac first tries a method that makes a real ARP request (`arping`, or `SendARP` through `ctypes` on Windows), and otherwise sends one empty UDP packet to the host on `settings.PORT` (55555 by default) so the OS adds the host to its table. `settings.ARP_TIMEOUT` controls how long getmac keeps checking the table afterwards. With `network_request=False`, getmac sends nothing and only reads what's already in the table.
3. **Pick a method.** Each way of getting a MAC is a `Method` subclass with a `method_type` (`ip4`, `ip6`, `ip` for both, `iface`, or `default_iface`), the `platforms` it supports, and whether it sends network traffic. `initialize_method_cache()` filters the `METHODS` registry by type and by the detected platform (or `settings.OVERRIDE_PLATFORM`), creates each candidate, and calls its `test()`, which is a cheap check such as "does this command exist" or "can this file be read". The first method that passes is cached for that type, and the others are kept as fallbacks. This happens once per method type per process, so later lookups don't pay for it again.
4. **Run it, and fall back if it fails.** `get_by_method()` calls the cached method's `get(arg)`. If `get()` raises, or the method marks itself unusable, getmac logs the problem, removes the method, and tries the next fallback. When every candidate has failed, a `RuntimeError` is raised, since that means the platform isn't supported or something changed underneath getmac.
5. **Clean the result.** Whatever the method found (a line of command output, the contents of a file, or a struct from a system call) goes through `utils.clean_mac()`, which returns a lowercase colon-separated MAC or `None` if the value isn't a valid MAC.

With no arguments, getmac finds the default interface first (step 3 with `default_iface` methods, which read the routing table), then looks up its MAC. If that interface has no MAC (a VPN tunnel, for example), the first interface with a MAC that isn't a loopback interface is used.

## Methods

The `METHODS` list in `getmac/getmac.py` is the registry, and its order is the order of preference within each type. Methods come in three kinds:

- **Files.** On Linux and Android, `/sys/class/net/<iface>/address` gives an interface's MAC, and `/proc/net/arp` is the ARP table. These are the fastest methods and are preferred where they exist.
- **System calls.** `fcntl` with `SIOCGIFHWADDR` on Linux, and `ctypes` calls into `iphlpapi.dll` on Windows. No subprocess, no parsing of text.
- **Commands.** `ip`, `arp`, `ifconfig`, `netstat`, `route`, `arping`, `lanscan`, `networksetup`, `getmac.exe`, `ipconfig.exe`, `netsh.exe`, and `wmic.exe`. getmac runs the command with `subprocess.check_output()` (never through a shell), discards stderr, and searches stdout with a regular expression written for that command's output format.

Each method is small and independent: it declares what it supports, checks whether it can run, and parses one format. A new platform or command version gets a new method and a new fixture of real command output in `tests/samples/`, rather than a change to an existing method's regular expression. That keeps a fix for one platform from breaking another.

## Platform detection

`consts` in `variables.py` detects the platform once, at import time, from `platform.system()`, `sys.platform`, and a few files (for example `/proc/version` to tell WSL1 from WSL2 and from Linux). The result is one of `android`, `darwin`, `linux`, `windows`, `wsl`, `openbsd`, `freebsd`, `sunos`, `hp-ux`, or `other`, and it's what methods are filtered on. `settings.OVERRIDE_PLATFORM` replaces it, which is how the test suite exercises every platform's methods on one machine.

Commands are found on a search path (`gvars.PATH`) that's copied from the process's `PATH` at import time. On POSIX systems `/sbin` and `/usr/sbin` are added, since `arp`, `ip`, and `ifconfig` often live there and a normal user's `PATH` may not include them. On Windows, Python `Scripts` directories are removed, so a pip-installed `getmac.exe` (this package's own command) or `ping.exe` can't be picked instead of the Windows command of the same name. Commands run with a copy of the environment that sets `LC_ALL=C`, so their output isn't translated.

## Testing

The test suite drives the methods with real captured command output in `tests/samples/<platform>_<version>/` and mocks `utils.popen()` and `utils.check_command()`, so the whole method set is tested on every platform and Python version in CI without running the actual commands. Coverage is measured for statements and branches, and CI fails if it drops below 90%. See [Contributing](contributing.rst) for the test policy, and [Adding methods](adding_methods.rst) for how to write a method and its test.

## Where to read more

- [Security policy](security.rst) and the [assurance case](assurance.md): what getmac does and doesn't do on your system, and why that's safe.
- [Module API](module_api.rst) and [Adding methods](adding_methods.rst): the `Method` class, the registry, and the cache functions.
- [rewrite.md](https://github.com/GhostofGoes/getmac/blob/main/docs/misc_docs/rewrite.md): the history of the 2020 rewrite that introduced this design.
