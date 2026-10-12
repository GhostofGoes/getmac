# Roadmap

This roadmap covers October 2026 to October 2027. The maintainer reviews it at each release, and each item links its issue when it has one. The full list of smaller tasks and known bugs is in [TODO.md](https://github.com/GhostofGoes/getmac/blob/main/docs/misc_docs/TODO.md).

getmac has the [OpenSSF Best Practices](https://www.bestpractices.dev/projects/9388) passing badge. Earning the silver badge, and then the gold badge, is a project goal.

## Planned

- **1.0.0 release.** Finish the rewrite that's been in progress on the `1.0.0-wip` branch: Python 3.9+ only, real type annotations, settings in the `settings` singleton, a `RuntimeError` when no method works, IPv6 and default interface support on Windows, and the published documentation site. See the [1.0.0 section of the CHANGELOG](https://github.com/GhostofGoes/getmac/blob/main/CHANGELOG.md).
- **OpenSSF Best Practices silver badge.** Governance, roadmap, architecture, and assurance documentation (this release), then the repository settings and people that the remaining criteria need: a named backup maintainer, DCO sign-offs, and a branch ruleset that requires code owner review. See [GOVERNANCE.md](https://github.com/GhostofGoes/getmac/blob/main/GOVERNANCE.md).
- **OpenSSF Best Practices gold badge.** Needs a second significant contributor, review of most changes by someone other than the author, and a security review (the first one is recorded in the [assurance case](https://ghostofgoes.github.io/getmac/assurance.html)). Statement and branch coverage are already above the gold thresholds, and CI enforces them.
- **Windows without WMIC.** A method for PowerShell's `Get-NetAdapter`, since WMIC is being removed from Windows 11 and `WmicExe` is the last fallback for interface lookups there.
- **Windows in other languages.** `ipconfig.exe` output is translated, so interface lookups by name only work in English. Collect samples from non-English Windows systems and match the translated headers.
- **IPv6 on macOS.** A method for `ndp -an`, since `arp` is IPv4-only on macOS.
- **Loopback and local addresses.** Treat every loopback address (`::1`, `127.0.0.2`, the host's own name) like `localhost`, and make the methods agree on the loopback interface's MAC.
- **VPN tunnels as the default interface.** When the default interface has no MAC (for example `utun0` on macOS), prefer the interface of another default route instead of the first interface with a MAC ([#91](https://github.com/GhostofGoes/getmac/issues/91)).
- **Reduce the cost of failures.** Check that an interface exists before looking up its MAC, and stop trying every method before failing.

## Under consideration

- **Get every MAC address on the host** in one call ([#77](https://github.com/GhostofGoes/getmac/issues/77)).
- **Interface indices** as an argument to `get_mac_address()`, using `socket.if_indextoname()` on POSIX and `wmic` or the Windows API on Windows.
- **Look up a MAC's IP address** (the reverse of what getmac does today).
- **Case-insensitive matching** of interface names and other arguments.
- **The MAC address of a Python socket's interface.**
- **Windows API methods** with `ctypes`, which wouldn't depend on the output format of commands.
- **Merging `ip` and `ip6`** into one argument that accepts either address family, deprecating `ip6`.

## Not planned

The project will not do these:

- Add runtime dependencies or compiled C extensions. getmac stays pure Python, standard library only, so it can be dropped into any project on any platform.
- Support Python 3.8 or older. Older versions of getmac are still on PyPI for them (see "Legacy Python versions" in the README).
- Collect data or send telemetry. The only network traffic getmac sends is the optional ARP/NDP table refresh, which can be turned off with `network_request=False`.
- Look up hosts outside the local layer 2 network. There's no reliable way to get the MAC of a host on another network.
- Become a general network inventory or scanning tool. getmac gets MAC addresses, one at a time.
