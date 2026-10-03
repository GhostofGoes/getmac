---
name: getmac
description: Look up the MAC address of a local network interface, or of a remote host on the LAN by IP or hostname, using the `getmac` Python package (CLI or library). Use whenever a task needs a MAC/hardware address, from the shell or from Python code.
license: MIT
---

`getmac` is a pure-Python, dependency-free package (`pip install getmac`,
Python 3.8+) with one job: given a local interface name, an IPv4/IPv6
address, or a hostname, return its MAC address. The common cases need no
root/admin. Full docs: https://ghostofgoes.github.io/getmac/

This skill covers **getmac 1.x**. Check the installed version with
`python -m getmac --version`. If it reports 0.9.x, see
[Older 0.9.x releases](#older-09x-releases) at the end.

## CLI

Prefer `python -m getmac` over the bare `getmac` command: on Windows, the
built-in `C:\Windows\System32\getmac.exe` usually shadows it on `PATH`.

The lookup modes are mutually exclusive, so pass at most one:

```bash
python -m getmac                    # MAC of the default interface
python -m getmac -i eth0            # local interface
python -m getmac -4 192.168.1.1     # remote IPv4 host
python -m getmac -6 fe80::1         # remote IPv6 host
python -m getmac -n router.lan      # hostname (resolved to IPv4 via DNS, then looked up)
```

**Output contract:** on success, stdout contains only the MAC (lowercase,
colon-separated, e.g. `00:0c:29:be:5c:9e`) and the exit code is `0`. On any
failure, stdout is empty and the exit code is `1`. Check the exit code
instead of matching text:

```bash
if mac=$(python -m getmac -i "$IFACE"); then
  echo "Found: $mac"
else
  echo "No MAC found for $IFACE" >&2
fi
```

Other flags:

| Flag | Effect |
|---|---|
| `-N`, `--no-net` | Don't run `arping` or send a UDP packet to refresh the ARP table first; only use what's cached. Faster, but likely to find nothing for a host not recently contacted. |
| `-v` / `-d` / `-dd` | Log progress / debug detail to **stderr**. stdout still carries only the MAC. |
| `--override-port PORT` | UDP port used to provoke an ARP entry (default `55555`). |
| `--override-platform`, `--force-method` | Debugging aids only. They bypass platform detection and method feasibility checks, so they won't make an unsupported lookup work. |

## Python API

```python
from getmac import get_mac_address, get_default_interface

get_mac_address()                     # default interface
get_mac_address(interface="eth0")
get_mac_address(ip="192.168.1.1")
get_mac_address(ip6="fe80::1")
get_mac_address(hostname="router.lan")
get_mac_address(ip="10.0.0.1", network_request=False)  # skip the ARP-refresh probe

get_default_interface()               # e.g. "eth0" (name, not MAC); not supported on Windows
```

Pass at most one of `interface` / `ip` / `ip6` / `hostname`. Inputs can be
`str` or `bytes` (decoded as UTF-8). `ip` and `ip6` also accept `ipaddress`
objects:

```python
import ipaddress

get_mac_address(ip=ipaddress.ip_address("192.168.1.1"))
get_mac_address(ip=ipaddress.ip_interface("192.168.1.1/24"))  # uses the host part
get_mac_address(ip=ipaddress.ip_address("fe80::1"))           # IPv6 object -> treated as ip6
```

A *string* passed to `ip` is always treated as IPv4; use `ip6` for IPv6
strings.

### Failures and exceptions

- **A lookup that finds nothing returns `None`.** This covers an unknown
  interface, an unreachable host and an unresolvable hostname. Errors inside
  the platform lookup methods are caught and logged, so check for `None`.
- **`ValueError`** means a bad argument: an `IPv4Network`/`IPv6Network`
  (getmac needs a host, not a network) or an unsupported type such as `int`.
- **`RuntimeError`** means getmac has no working lookup method for this kind
  of request on this platform, e.g. none of the commands it relies on are
  available. Retrying won't help; it's an environment problem, or a bug worth
  reporting upstream.

### Settings

Settings live on the `getmac.settings` object. Set them before calling:

```python
import getmac

getmac.settings.DEBUG = 2     # 0 (off) to ~4; logs via the "getmac" logger
getmac.settings.PORT = 44444  # UDP port for the ARP-refresh probe
```

To see the debug output, configure `logging` (e.g. `logging.basicConfig()`).
`settings` also has `OVERRIDE_PLATFORM` and `FORCE_METHOD`, the library
equivalents of the CLI debugging flags.

## Gotchas

- **The target must be on the local network.** MACs aren't visible across
  routers, so `-4 8.8.8.8` returning nothing is expected, not a bug.
- **Failures are indistinguishable.** A nonexistent interface and an
  unreachable host both give `None` / exit code 1 with empty stdout.
- **`localhost` / `127.0.0.1` return `00:00:00:00:00:00`.**
- **The first call is slower.** getmac probes which platform commands work
  and caches the result for the rest of the process, so later calls are
  faster.

## Older 0.9.x releases

If 0.9.x is installed (the last line supporting Python 2.7–3.7), the core
`get_mac_address()` call and CLI flags are the same, except:

- There's no `get_default_interface()` or `getmac.settings`. Set
  `getmac.getmac.DEBUG` / `getmac.getmac.PORT` module attributes instead.
- `ipaddress` objects aren't accepted. Pass strings.
- On Python 2, the console script is `getmac2`.
