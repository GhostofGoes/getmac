# Security Policy

## Supported Versions

| Version    | Supported          |
| ---------- | ------------------ |
| 1.0.x      | Yes |
| 0.9.x      | Maintenance mode, security or major bug fixes only |
| 0.8.x      | No longer supported |
| <= 0.7.x   | No longer supported |

## Security model

getmac works by running platform commands (`ip`, `arp`, `ifconfig`, `getmac.exe`,
`netsh.exe`, and others), reading files under `/proc` and `/sys`, and sending a
network packet to populate the ARP/NDP table. What this means for a program using
getmac:

* **Inputs are treated as untrusted.** The `interface`, `ip`, `ip6`, and `hostname`
  arguments to `get_mac_address()` are validated. IP addresses are parsed with the
  standard library's `ipaddress` module, and interface names that could be read as
  command-line options or contain unusual characters are rejected with a `ValueError`.
  A program can pass values from an untrusted source (such as a web request), though
  validating them itself as well is good practice.
* **Commands are never run through a shell.** Arguments are passed to the command
  directly, so shell metacharacters have no special meaning, and a user-supplied value
  is always a single argument.
* **Commands are found in the `PATH` only.** getmac only runs a command found in an
  absolute directory on the `PATH`. It never runs a command from the current directory
  or a relative `PATH` entry, which avoids running a program planted next to the one
  getmac is calling. On POSIX, `/sbin` and `/usr/sbin` are added to the `PATH`, since
  the commands are often there and not on a non-root user's `PATH`.
* **Network requests.** Looking up the MAC of a remote host sends an empty UDP packet
  to the host (see the `network_request` argument and the `PORT` setting), and
  resolving a hostname does a DNS lookup. On Windows, finding the default interface
  opens a UDP socket to a public DNS server (`1.1.1.1`) to learn which interface has
  the default route; no packet is sent to it. Pass `network_request=False` to avoid
  sending the UDP packet and using commands that make network requests (such as
  `arping`).
* **The environment is inherited.** Commands run with getmac's environment, which is a
  copy of the calling process's environment with `LC_ALL=C` added. If that environment
  has secrets in it, they're visible to the commands getmac runs, as with any
  subprocess.

## Reporting a Vulnerability or other security issue

If the security issue is a general weakness or poor practice that is *not directly exploitable*, please open a [Issue on GitHub](https://github.com/GhostofGoes/getmac/issues) and add the `security` label.

If the security issue is a vulnerability that can *potentially be exploited or has a exploit developed/proven*, please email ghostofgoes(at)gmail.com.
Please include in the email a description of the vulnerability, any proof of concept code/exploit code, and any other information that you believe may be relevant.
PGP signed message is preferred but not required.
