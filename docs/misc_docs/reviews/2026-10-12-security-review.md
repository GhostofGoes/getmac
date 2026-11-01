# Security review, 2026-10-12

A review of getmac 1.0.0 (the `main` branch at commit `fd97607`) against the security requirements and the trust boundaries in [docs/assurance.md](../../assurance.md). It was done with AI assistance (Claude) as part of the work toward the OpenSSF Best Practices silver and gold badges, and the maintainer checked the findings and the fix. It's recorded here so the next review has something to compare against.

## What was reviewed

- `getmac/getmac.py`: `get_mac_address()`, `get_default_interface()`, the method cache and fallback logic, and every `Method` subclass that runs a command, reads a file, makes a system call, or sends traffic.
- `getmac/utils.py`: `popen()`, `call_proc()`, `check_command()`, `read_file()`, `search()`, `clean_mac()`, and `fetch_ip_using_dns()`.
- `getmac/variables.py`: the search path and environment for commands, and the platform detection.
- `getmac/__main__.py`: the command line parser.
- `.github/workflows/`: permissions, pinning, credential handling, and the release path.
- `packaging/Dockerfile`: the user the image runs as, and what's installed.

The questions asked for each piece were: what does the caller control, where does it go, what program or file does it reach, and what comes back.

## Findings

### 1. IP address strings weren't validated before becoming command arguments (fixed)

`get_mac_address(ip=...)` and `ip6=...` accepted any string. `ipaddress` objects were converted to strings, but a string was passed through as is. Several methods put the value into a command's arguments: `arp -a <ip>` and `arp.exe -a <ip>`, `arping ... <ip>`, `ip neighbor show <ip>`, and `netsh.exe int ipv6 show neigh` (then matched against output). The only check for `ip6` was that it contained a colon.

Because `call_proc()` never uses a shell, a value couldn't start a second command. On POSIX, the arguments are split with `shlex.split()` into a list, so a value such as `192.168.0.1 -n` became two arguments to `arp`, and a value starting with `-` became an option. That's argument injection (CWE-88), not command injection, and the commands involved only read the ARP table, so the impact was low: an unexpected option could change the command's output or make it fail, which getmac treats as "not found". On Windows, `call_proc()` passes one command string to `CreateProcess` (still no `cmd.exe`), with the same effect.

Fix: `get_mac_address()` now parses string addresses with `ipaddress.IPv4Address` and `IPv6Address` (which accepts scoped addresses such as `fe80::1%eth0`) and returns `None` with a logged error when they don't parse, before any method runs or any packet is sent. Tests in `tests/test_getmac.py` cover option-like and malformed values for both arguments.

### 2. Interface names are passed as one argument (no change needed)

`interface` is used as an argument to `ifconfig <iface>`, `ip link show <iface>`, and `networksetup -getmacaddress <iface>`, and as a path component in `/sys/class/net/<iface>/address`. On POSIX, `shlex.split()` splits a name with spaces into several arguments. Real interface names on POSIX don't contain spaces (the kernel limits them to 15 characters without whitespace or `/`), and on Windows, where names do contain spaces, the interface methods parse the whole output of `getmac.exe`, `ipconfig.exe`, and `wmic.exe` rather than passing the name as an argument. A name such as `../../etc/passwd` would make `SysIfaceFile` read a file outside `/sys/class/net/`, but `read_file()` only reads, the contents are matched against a MAC address regular expression, and nothing else is done with them, so there's no disclosure. Not changed, but noted in the assurance case so that a future Windows method that passes the name as an argument validates it.

### 3. Commands are found on the process's search path (accepted risk)

`popen()` walks `gvars.PATH` for an executable with the command's name, so a program named `arp` earlier on the path runs instead of the system one. This is inherent in running system commands and is the same for every program that does so. The mitigations in place are reasonable: on Windows, Python `Scripts` directories are removed from the path so a pip-installed `getmac.exe` or `ping.exe` can't shadow the Windows commands, and on Linux the file and system call methods come before the command methods. No change.

### 4. Network traffic is minimal and opt-out (no change needed)

With `network_request=True`, getmac sends one empty UDP packet to the named host on `settings.PORT`, or runs `arping` or `SendARP`, which send one ARP request. On Windows it also connects a UDP socket to `1.1.1.1:53` to learn the default interface's address, which sends no application data but does cause a packet. All of it is skipped with `network_request=False`. `settings.PORT` is an integer that the command line parses with `int`. No change, but the `1.1.1.1` connect is now called out in the security policy, since users with strict egress rules will want to know.

### 5. Subprocess environment and output handling (no change needed)

`call_proc()` runs commands with a copy of the environment that sets `LC_ALL=C`, discards stderr, and decodes stdout as UTF-8 (then the OEM code page on Windows, with replacement). Output is only searched with regular expressions. The `IpconfigExe` regular expression was already rewritten in 1.0.0 to stop catastrophic backtracking. The remaining expressions were read for unbounded nested repetition and none was found.

### 6. CI and release path (no change needed)

Every action is pinned to a commit SHA, checkouts set `persist-credentials: false`, the default token is read-only, and the publish job is the only one with `id-token: write`, guarded by an environment, a tag pattern, and a repository check. Packages and the container image are attested. This review added OpenSSF Scorecard and zizmor workflows so these properties are checked continuously rather than by hand.

### 7. Docker image (no change needed)

The image runs as `nobody`, installs only `iproute2` on top of the base image, applies Debian security updates at build time, and doesn't keep pip or the source in the final layer.

## What wasn't reviewed

- The documentation site's build and hosting (static pages on GitHub Pages).
- The samples in `tests/samples/` for leftover private data. They were anonymised when added; this review didn't re-check every file.
- Behaviour on platforms the maintainer can't test (HP-UX, Solaris, Android without BusyBox).

## Next review

Do the next review before the first release that changes a trust boundary, or in five years at the latest, whichever comes first. Start from the table in `docs/assurance.md` and check each row's evidence still holds.
