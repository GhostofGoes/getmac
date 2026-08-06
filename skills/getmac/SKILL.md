---
name: getmac
description: Get the MAC (hardware/Ethernet) address of a local network interface or a remote host on the LAN, using the `getmac` CLI or Python library (`pip install getmac`). Use when asked to look up, find, or resolve a MAC address / hardware address / NIC address for a network interface, IP address, or hostname, either from the command line or inside a Python script.
---

`getmac` is a small, dependency-free Python package providing a CLI and a
library function for one job: given a local interface name, an IP/IPv6
address, or a hostname, return its MAC address. It requires no special
privileges (no root/admin needed) for the common cases below.

This skill covers the **currently published PyPI release (`getmac` 0.9.5)**
— the version `pip install getmac` actually gives you today. Don't assume
newer-looking APIs from the project's GitHub `README` at the tip of its
`main` branch or other in-development branches are already released; verify
with `pip show getmac` / `getmac --version` if in doubt.

## Install

```bash
pip install getmac
```

Puts a `getmac` executable on `PATH` and makes `import getmac` available.
No compiled dependencies — pure Python, works the same via `pipx install
getmac` if you want it isolated from a project's own environment.

## CLI usage

```bash
getmac --help          # or: python -m getmac --help (identical, same argparse)
getmac --version        # -> getmac 0.9.5
```

The four lookup modes are mutually exclusive — pass at most one:

```bash
getmac                          # no args: MAC of the default network interface
getmac -i eth0                  # MAC of a named local interface
getmac -4 192.168.1.1           # MAC of a remote IPv4 host (populates ARP table first)
getmac -6 fe80::1               # MAC of a remote IPv6 host
getmac -n router.lan            # MAC of a host by hostname (resolved via DNS, then looked up)
```

Verified against a real machine (interface `ens33`, an IP already present in
its ARP table):

```
$ getmac
00:0c:29:be:5c:9e
$ getmac -i ens33
00:0c:29:be:5c:9e
$ getmac -4 192.168.235.2
00:50:56:e6:19:8a
$ getmac -n localhost
00:00:00:00:00:00
```

**Output contract**: on success, the MAC (lowercase, colon-separated, e.g.
`00:0c:29:be:5c:9e`) is the *only* thing printed to stdout, and the process
exits `0`. On failure (interface doesn't exist, host unreachable/not in
ARP table, etc.) **nothing is printed to stdout and the exit code is `1`** —
this is the reliable way to detect success/failure in a script, not text
matching:

```bash
if mac=$(getmac -i "$IFACE_NAME") && [[ -n "$mac" ]]; then
  echo "Found: $mac"
else
  echo "Could not resolve a MAC for $IFACE_NAME" >&2
fi
```

Useful flags:

| Flag | Effect |
|---|---|
| `-N`, `--no-net` | Don't send a UDP packet / use `arping` to refresh the ARP table before an IP/hostname lookup — only use what's already cached. Faster, but more likely to return nothing for a host not recently contacted. |
| `-v`, `--verbose` | Log progress messages to **stderr** (stdout still carries only the final MAC). |
| `-d`, `--debug` | More detail than `-v`; stack with `-dd` for even more. All still on stderr. |
| `--override-port PORT` | Change the UDP port used to "ping" a host into populating the ARP table (default `55555`). |
| `--override-platform PLATFORM` | Force platform-specific lookup logic (e.g. `linux`, `windows`, `freebsd`) instead of auto-detecting. Mainly a debugging aid — don't use to make an incompatible method work, it won't. |
| `--force-method METHOD` | Force one specific internal lookup method by name, bypassing normal fallback. Debugging-only; skips the method's own feasibility check. |

## Python API

```python
from getmac import get_mac_address

get_mac_address(interface="eth0")
get_mac_address(ip="192.168.1.1")
get_mac_address(ip6="fe80::1")
get_mac_address(hostname="router.lan")
get_mac_address(ip="10.0.0.1", network_request=True)  # default; set False to skip the ARP-refresh probe
```

Verified directly:

```python
>>> from getmac import get_mac_address
>>> get_mac_address(interface="ens33")
'00:0c:29:be:5c:9e'
>>> get_mac_address(ip="192.168.235.2")
'00:50:56:e6:19:8a'
>>> get_mac_address(interface="does-not-exist")
None
```

**On failure this returns `None`, it does not raise.** Internally, exceptions
from platform-specific lookup methods are caught and logged, not propagated
— so always check for `None` rather than wrapping calls in `try`/`except`.

`interface`/`ip`/`ip6`/`hostname` are mutually exclusive — pass exactly one,
or none to get the default interface's MAC.

### Runtime settings (module-level, not function args)

```python
from getmac import getmac as _getmac_internals

_getmac_internals.DEBUG = 2        # 0 (off) .. ~4 (max) — logs via the "getmac" logger
_getmac_internals.PORT = 44444     # UDP port for the ARP-refresh probe, default 55555
```

These are plain module attributes on the internal `getmac.getmac` module
(there is no separate `settings` object in this release) — set them before
calling `get_mac_address()`. Debug/verbose output goes through Python's
`logging` module under the logger name `"getmac"`; configure it the normal
way (`logging.basicConfig(...)`) to actually see the messages.

## Gotchas

- **`get_default_interface` is not available in this release.** It only
  exists on getmac's in-development branches, not in the published 0.9.5
  on PyPI — `from getmac import get_default_interface` raises `ImportError`
  today. To get the MAC of the default interface, just call
  `get_mac_address()` with no arguments (CLI: `getmac` with no flags) —
  that already resolves the default interface internally.
- **A nonexistent interface name and an unreachable/unknown IP behave the
  same way**: CLI exits 1 with empty stdout, library call returns `None`.
  There's no separate "interface doesn't exist" vs. "host not found" signal
  — don't try to distinguish them from the return value alone.
- **`getmac -v`/`-d` output goes to stderr, not stdout** — if you're
  capturing output in a script, `$(getmac -v ...)` via normal command
  substitution is safe (stderr isn't captured), but don't parse `2>&1`
  combined output expecting the MAC to be on a predictable line.
- **IP/hostname lookups need the target to be on the same LAN /
  broadcast domain.** There is no way to get a MAC for a host outside the
  local network — `getmac -4 8.8.8.8` will not work and isn't a bug.
- **Windows/macOS/BSD-specific behavior** (e.g. `arp.exe`, `wmic.exe`,
  `networksetup` on macOS) is documented in the upstream README but wasn't
  exercised for this skill — it was verified only on Linux. Don't assume
  parity; if it matters, test on the actual target platform.
