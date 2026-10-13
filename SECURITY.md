# Security Policy

## Supported Versions

| Version    | Supported          |
| ---------- | ------------------ |
| 1.0.x      | Yes |
| 0.9.x      | Maintenance mode, security or major bug fixes only |
| 0.8.x      | No longer supported |
| <= 0.7.x   | No longer supported |

## What to expect

getmac is a library and command that asks your operating system for MAC addresses. It runs with your permissions and nothing more. These are its security properties, and the [assurance case](https://ghostofgoes.github.io/getmac/assurance.html) explains why they hold:

- It has no runtime dependencies and no compiled extensions. Everything it does is in the standard library.
- It reads only the files and runs only the commands your operating system provides for network information (`/proc` and `/sys` files, `arp`, `ip`, `ifconfig`, `ipconfig.exe`, and the others listed in the README). Commands are never run through a shell, and their names are fixed in the code.
- IP address arguments must parse as an IP address of the right family before they're used, so they can't become extra command arguments.
- It writes nothing: no files, no configuration, no cache on disk.
- It sends network traffic only when looking up a remote host with `network_request=True` (the default): one empty UDP packet to the host on port 55555 (`settings.PORT`), or one ARP request with `arping` or the Windows `SendARP` call. On Windows it also connects a UDP socket to `1.1.1.1:53` to find the default interface's address. With `network_request=False` (`--no-network-requests` on the command line), it sends nothing at all and only reads what's already in the ARP/NDP table.
- It collects no data and has no telemetry.
- Releases are built and published by CI with no stored credentials, and every sdist, wheel, and container image has a signed build provenance attestation you can verify.

getmac can't protect you from these:

- A host on your local network that lies in its ARP or NDP replies. ARP and NDP have no authentication, so the MAC getmac reports is what your operating system was told. Don't use a MAC address as proof of identity.
- A system where a program on the `PATH` has replaced a system command such as `arp`, or where `/proc` has been changed. getmac trusts the operating system.
- A copy of getmac that didn't come from PyPI, the GitHub Container Registry, or this repository, or that you didn't verify.

## How reports are handled

1. We acknowledge your report within 7 days.
2. We check the report and tell you whether we can reproduce the problem and how severe we think it is, usually within 14 days.
3. We make the fix in private, in a temporary private fork of a GitHub security advisory.
4. We publish a patch release with the fix, for the versions in the table above. Then we publish the advisory, and request a CVE ID when the problem needs one. The release notes and the CHANGELOG name the advisory.
5. The advisory and the release notes give credit to you, unless you ask not to be named.

We aim to fix a confirmed vulnerability within 60 days of the report, and a critical one much sooner. We keep you informed at each step, and if we don't agree that a report is a vulnerability, we tell you why.

## Reporting a Vulnerability or other security issue

If the security issue is a general weakness or poor practice that is *not directly exploitable*, please open a [Issue on GitHub](https://github.com/GhostofGoes/getmac/issues) and add the `security` label.

If the security issue is a vulnerability that can *potentially be exploited or has a exploit developed/proven*, please email ghostofgoes(at)gmail.com.
Please include in the email a description of the vulnerability, any proof of concept code/exploit code, and any other information that you believe may be relevant.
PGP signed message is preferred but not required.
