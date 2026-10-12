# Assurance case

This page explains why getmac meets the security properties that the [security policy](security.rst) describes. It gives the threat model, the trust boundaries, the secure design principles the project applies, and how common weaknesses are countered. Each claim names the code, test, or check that backs it up. The [architecture](architecture.md) page describes the pieces this page refers to.

Update this page when a change moves a trust boundary: a new way of running commands, a new file or environment variable that's read, a new kind of network traffic, or a new dependency.

## Scope

The case covers the `getmac` package as published to PyPI (the library and the `getmac` command), the Docker image, and the process that builds and publishes them. It doesn't cover the documentation site, which is static pages built by Sphinx with no forms, accounts, or scripts from other sites.

## Threat model

getmac runs inside the caller's process, with the caller's permissions, and asks the operating system for information it already has. It keeps no secrets, stores nothing, and listens on nothing. The assets to protect are:

- **The caller's process and account.** Arguments to `get_mac_address()` must not make getmac run a different program, run a program with different arguments than intended, read a file the caller didn't expect, or write anything.
- **The network.** getmac must not send traffic the caller didn't ask for, and what it sends must be harmless: one empty UDP packet, or one ARP request, to the host the caller named.
- **The integrity of the package.** `pip install getmac` and `docker pull ghcr.io/ghostofgoes/getmac` must give the user what the source on `main` builds.

The attackers the project considers:

| Attacker | What they can do |
|---|---|
| The caller's input | Pass any string or bytes as the `interface`, `ip`, `ip6`, or `hostname` argument, or on the command line. For example, a web application that looks up a MAC for an address a user typed. |
| A host on the local network | Answer ARP or NDP with any MAC, reply to the UDP packet, or not reply at all. |
| The DNS resolver | Resolve a hostname to any address. |
| A local user on a shared system | Put a program with the name of a system command (such as `arp`) somewhere on the `PATH`, or change the output of a command. |
| A compromised dependency or CI action | Put code into the build or the published package. |
| A contributor | Send a pull request that changes the code, the tests, or the workflows. |

Out of scope: an attacker who already controls the caller's account or the operating system, and a copy of getmac that didn't come from PyPI, the GitHub Container Registry, or this repository. getmac can't tell whether the MAC the operating system reports is the real one, since ARP and NDP have no authentication. It reports what the OS knows.

## Trust boundaries

| # | Boundary | What crosses it | Control |
|---|---|---|---|
| B1 | Caller to getmac | The arguments to `get_mac_address()` and the command line options | `get_mac_address()` accepts one argument at a time, decodes `bytes` as UTF-8, converts `ipaddress` objects, and rejects IP address strings that don't parse as an address of the right family (`ipaddress.IPv4Address` and `IPv6Address`) with a logged error and `None`. The command line uses `argparse` with typed, mutually exclusive options, and `--arp-timeout` must be a number of seconds that's zero or more. Tests: `tests/test_getmac.py` (`test_get_mac_address_invalid_types`, `test_get_mac_address_invalid_ip_strings`) and `tests/test_cli.py`. |
| B2 | getmac to other programs | A command name and its arguments | `utils.popen()` finds the command by trying each directory on `gvars.PATH` for an executable file of that name, and `utils.call_proc()` runs it with `subprocess.check_output()` without a shell: as an argument list built with `shlex.split()` on POSIX, and as a plain command string on Windows (no `cmd.exe`). stderr is discarded and `LC_ALL=C` is set. Command names are fixed string literals in each method; the only user-controlled part is the interface name or the validated address. Tests: `tests/test_utils.py`. |
| B3 | Other programs and files to getmac | Command output, `/proc` and `/sys` files | Output is text that's only searched with regular expressions written for one command's format, and the matched value is checked by `utils.clean_mac()` before it's returned. Nothing in the output is executed or evaluated. Each parser is tested against real captured output in `tests/samples/`. The `IpconfigExe` regular expression was rewritten in 1.0.0 so it can't backtrack catastrophically on unexpected output. |
| B4 | getmac to the network | One empty UDP packet to `settings.PORT`, or one ARP request (`arping`, or `SendARP` on Windows), to the named host, and on Windows one UDP connect to `1.1.1.1:53` to find the default interface's address | Only when `network_request` is true, and only to the address the caller gave. Nothing is sent for interface lookups. `network_request=False` (`--no-network-requests`) sends nothing at all. Tests: `tests/test_getmac.py`. |
| B5 | Source to published package | The build | `ci.yml` builds the sdist and wheel in a job with read-only permissions, and only the `publish-pypi` job can get a PyPI token, through Trusted Publishing (OpenID Connect, no stored token). It runs only for version tags pushed to this repository, after lint, tests, docs, and build pass, and needs a deployment approval. PEP 740 attestations are uploaded to PyPI, and build provenance attestations are stored on GitHub. `docker.yml` does the same for the container image, with SBOM and provenance attestations. |
| B6 | Published package to the user | Downloads | PyPI and the GitHub Container Registry serve over HTTPS only. The security policy says how to verify the attestations with `gh attestation verify`. |

## Secure design principles

The principles of Saltzer and Schroeder, as getmac applies them:

- **Economy of mechanism.** One package, no runtime dependencies, no C extensions, no configuration files, no plug-ins, no background threads, and no state that outlives the process except a cache of which methods work. Everything that touches the system goes through two functions in `getmac/utils.py`.
- **Fail-safe defaults.** A lookup that fails returns `None` and logs why. An invalid address is rejected rather than guessed at. `settings.DEBUG` is off by default, so nothing about the system is logged unless the caller asks. The only thing getmac does on import is detect the platform; no command runs until a lookup is made.
- **Least privilege.** getmac needs no special permissions. Methods that would need root (such as `arping`) are skipped when they aren't available or fail. The Docker image runs `getmac` as `nobody`. CI workflows have read-only permissions by default, and each job asks for exactly what it needs; the PyPI token is only reachable through a protected environment.
- **Complete mediation.** Every argument goes through `get_mac_address()`'s normalisation and validation before any method sees it, and every result goes through `clean_mac()` before the caller sees it. Methods can't bypass either.
- **Open design.** The source, the tests, the workflows, and this case are public. The security comes from the checks, not from secrecy.
- **Separation of privilege.** `main` accepts only pull requests that pass CI and a code owner's review ([GOVERNANCE.md](https://github.com/GhostofGoes/getmac/blob/main/GOVERNANCE.md)). Only the maintainer can create release tags, and a release needs a deployment approval on top of that.
- **Least common mechanism.** getmac shares nothing between callers or processes. It reads the ARP table; it never changes it beyond what one packet to the named host causes the OS to do.
- **Psychological acceptability.** The simple call, `get_mac_address(ip="192.168.0.1")`, is the safe one. Turning off network requests is one keyword argument.

## Common weaknesses and how they're countered

| Weakness (CWE) | Where it could occur | Counter | Evidence |
|---|---|---|---|
| OS command injection (CWE-78) | Commands built from the caller's arguments | No shell is ever used. Command names are literals. On POSIX the arguments are a list, so a value can't become a new command. | `utils.call_proc()`; ruff's `flake8-bandit` rules (`S`) run in CI and flag `shell=True`. |
| Argument injection (CWE-88) | An `ip` or `ip6` value such as `-x` passed to `arp` or `ip neighbor show` | Address strings must parse as an IP address before any method runs, so they can't start with `-` or contain spaces. Interface names are passed as a single argument. | `get_mac_address()` validation and its tests. |
| Untrusted search path (CWE-426) | A program named `arp` placed earlier on the `PATH` | getmac can't fully prevent this, since it has to find system commands somewhere, and that's true of any program that runs them. It reduces the risk: on Windows, Python `Scripts` directories (where pip installs executables, including this package's own `getmac.exe`) are removed from the search path, and files are preferred over commands where both exist. | `Variables.__init__()` in `getmac/variables.py`; `METHODS` order. |
| Regular expression denial of service (CWE-1333) | Parsers of command output | Regular expressions are anchored or bounded, and the one found to backtrack (`IpconfigExe`) was rewritten. | Sample-driven tests in `tests/test_methods.py`. |
| Improper input validation (CWE-20) | The `ip`, `ip6`, `hostname`, and `interface` arguments | Addresses are validated with the `ipaddress` module. `bytes` that aren't UTF-8 raise `UnicodeDecodeError` to the caller. Hostnames go only to the system resolver. | `get_mac_address()` and `tests/test_getmac.py`. |
| Uncontrolled resource use (CWE-400) | `settings.ARP_TIMEOUT` | The timeout is bounded by the value the caller sets, zero by default, and the command line rejects negative values. | `tests/test_cli.py`. |
| Information exposure through logs (CWE-532) | Debug output includes command output and addresses | Logging goes to the `getmac` logger with a `NullHandler`, so nothing is printed unless the caller configures logging and raises `settings.DEBUG`. | `getmac/variables.py`. |
| Vulnerable or malicious dependency (CWE-1395) | Development tools and CI actions (there are no runtime dependencies) | Development tools are pinned in `pdm.lock`, which CI checks against `pyproject.toml`. GitHub Actions are pinned to commit SHAs. zizmor audits the workflows, and CodeQL and OpenSSF Scorecard run weekly. | `.github/workflows/`, `pdm.lock`. |
| Leaked credentials (CWE-798) | The repository | No credential is stored: PyPI uses Trusted Publishing and the registry uses the workflow's own token. GitHub secret scanning and push protection are on. Checkouts in CI don't persist credentials. | `ci.yml`, `docker.yml`. |
| Tampered build (CWE-506) | CI | Packages are built in a job without secrets, published from the built artifact by a separate job, and attested. Users can verify the attestations. | `ci.yml` (`build` and `publish-pypi`), `docker.yml`, `SECURITY.md`. |
| Memory safety (CWE-119 and friends) | Not applicable to Python, except through foreign calls | The two foreign calls (`SendARP` through `ctypes` on Windows, and `fcntl.ioctl` with `SIOCGIFHWADDR` on Linux) use fixed-size buffers that the OS fills, with their sizes passed explicitly. | `CtypesHost` and `FcntlIface` in `getmac/getmac.py`. |

## Analysis tools

- **Static analysis.** ruff with the `flake8-bandit` (`S`), `flake8-bugbear` (`B`), and pylint rule sets, mypy with type checking of the whole package, vulture for dead code, and codespell, all on every push and pull request (`pdm run lint`). CodeQL runs on every pull request and weekly.
- **Dynamic analysis.** The test suite runs on every push and pull request across Linux, macOS, and Windows and every supported Python version, with Python's warnings turned into errors, assertions enabled, and the tests run in random order. Statement and branch coverage are measured, and CI fails below 90%.
- **Supply chain.** OpenSSF Scorecard and zizmor run on the workflows, and their results go to code scanning.

## Security reviews

- **2026-10-12.** A review of the input handling, command execution, and network paths of the 1.0.0 code, done with AI assistance and checked by the maintainer. It found that IP address strings weren't validated before being used as command arguments (fixed in the same change), and confirmed the boundaries above. The notes are in [docs/misc_docs/reviews/2026-10-12-security-review.md](https://github.com/GhostofGoes/getmac/blob/main/docs/misc_docs/reviews/2026-10-12-security-review.md).

## Residual risks

- One person holds the repository's owner rights, the PyPI project, and the ability to tag a release. [GOVERNANCE.md](https://github.com/GhostofGoes/getmac/blob/main/GOVERNANCE.md) describes the plan for a backup maintainer.
- getmac has to trust the operating system's commands and files. A program earlier on the `PATH` with a system command's name, or a modified `/proc` file, can feed getmac false output. This is a property of the approach, not something getmac can fix, and it's why getmac prefers files and system calls over commands where it can.
- The MAC an ARP or NDP table reports is whatever the network said. An attacker on the local network can spoof it. getmac has no way to detect this and doesn't claim to.
- On Windows, `call_proc()` passes the command as one string rather than a list, because of how some Windows commands parse their arguments. The validation at B1 is what keeps that safe, so a new argument that reaches a Windows command must be validated the same way.
