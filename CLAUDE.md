# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`getmac` is a pure-Python, dependency-free library and CLI that gets the MAC address of local network interfaces or remote hosts on the LAN. It must run across many OSes (Windows, Linux, macOS/Darwin, WSL1/WSL2, BSDs, Solaris, HP-UX, Android) without any C-extensions, so all platform logic is implemented by shelling out to platform commands (`arp`, `ip`, `ifconfig`, `netstat`, `ipconfig.exe`, `wmic.exe`, `arping`, `networksetup`, `lanscan`, etc.), reading `/proc` or `/sys` files, or using stdlib features (`fcntl`, `ctypes`).

**This is the `1.0.0-wip` branch** — an in-progress rewrite/modernization targeting Python 3.8+ only (Python 2, PyPy2, IronPython, and Jython support has been dropped). Don't reintroduce Python-2-compatible patterns (`# type: (...) -> ...` comments, `from __future__ import`, `six`-style shims) — this branch uses real type annotations and f-strings throughout. The `main` branch is still the 0.9.x line and is structured differently (single-file `getmac/getmac.py` with module-level globals) — don't assume patterns from `main` apply here.

## Package layout

- `getmac/getmac.py` — the `Method` base class, every platform-specific `Method` subclass, the `METHODS` registry, the method-selection/fallback cache machinery, and the public `get_mac_address()` / `get_default_interface()` functions.
- `getmac/variables.py` — all module-level state, split into three classes instantiated once as singletons: `settings` (user-configurable: `DEBUG`, `PORT`, `OVERRIDE_PLATFORM`, `FORCE_METHOD`), `consts` (immutable platform detection results: `WINDOWS`, `DARWIN`, `LINUX`, `WSL1`, `WSL2`, `BSD`, `PLATFORM`, MAC regexes, etc.), and `gvars` (other mutable globals: `PATH`, `ENV`, `log`, `CHECK_COMMAND_CACHE`, `DEFAULT_IFACE`). Import these as `from .variables import consts, gvars, settings` and access via e.g. `settings.DEBUG`, `consts.WINDOWS`, `gvars.log` — not as bare module-level names.
- `getmac/utils.py` — standalone helper functions used by methods: `check_command`, `check_path`, `clean_mac`, `read_file`, `search`, `popen`, `call_proc`, `fetch_ip_using_dns`. Imported as `from . import utils` and called as `utils.popen(...)`, etc.
- `getmac/__main__.py` — CLI entry point (`build_parser()` + `main()`), imports `getmac` and `variables`.
- `getmac/__init__.py` — public exports.

## Commands

This branch uses **PDM**, not tox/setup.py (those belong to `main`/0.9.x). Install PDM first (https://pdm-project.org), then:

```bash
# Create the dev environment (installs test, lint, and docs dependency groups)
pdm install -d

# Run the full test suite (mirrors what CI's "test" job runs; benchmarks disabled, coverage on)
pdm run test

# Run a single test file / test — extra args are passed through to the underlying pytest call
pdm run test tests/test_methods.py
pdm run test tests/test_methods.py::test_darwinnetworksetupiface
pdm run test -k ifconfig

# Run the test suite with benchmarking enabled instead of disabled (coverage flags omitted)
pdm run benchmark

# Run all lint/static-analysis checks (what CI's "lint" job runs)
pdm run lint

# Auto-format code (required before submitting a PR)
pdm run format

# Build Sphinx docs (HTML + manpage)
pdm run docs

# Run the CLI from source
pdm run getmac --help

# List all available PDM scripts
pdm run -l
```

`pdm run lint` runs, in order: `spelling` (codespell), `check` (ruff check), `unused` (vulture, dead code), `check_format` (ruff import-sort + format check), `typing` (mypy). Run this locally before committing. Ruff config (rule selection, per-file ignores, line length 99) lives in `pyproject.toml` under `[tool.ruff]`.

## Architecture: the `Method` pattern

The core abstraction, in `getmac/getmac.py`, is `Method` — a class with `test()` (cheap feasibility check, e.g. "does this command exist") and `get(arg)` (does the actual lookup, may raise). Every platform-specific technique is a `Method` subclass, registered in the `METHODS` list near the bottom of the file.

Each `Method` declares:
- `platforms`: set of platform strings it supports, from `Method.VALID_PLATFORM_NAMES` (`android`, `darwin`, `linux`, `windows`, `wsl`, `openbsd`, `freebsd`, `sunos`, `hp-ux`, `other`)
- `method_type`: `ip` (valid for both `ip4`/`ip6`), `ip4`, `ip6`, `iface`, or `default_iface`
- `network_request`: whether calling it sends traffic on the wire (e.g. `ArpingHost`)

At runtime, `initialize_method_cache(method_type, network_request)` filters `METHODS` by type and current platform (`consts.PLATFORM`, or `settings.OVERRIDE_PLATFORM`), instantiates each candidate, and calls `.test()`. The first one that passes is cached in `METHOD_CACHE[method_type]`; the rest become fallbacks in `FALLBACK_CACHE[method_type]`. `get_by_method()` uses the cached method, and `_attempt_method_get()` / `_remove_unusable()` automatically fall back to the next candidate if a method raises or sets `self.unusable = True`. Unlike the 0.9.x line, exhausting all candidates now raises `RuntimeError` instead of returning `None` silently.

`get_mac_address()` is the single public entry point (re-exported from `getmac/__init__.py`, alongside the newer `get_default_interface()`). It:
1. Normalizes `bytes` arguments to `str`, and accepts `ipaddress.IPv4Address`/`IPv4Interface`/`IPv6Address`/`IPv6Interface` objects for `ip`/`ip6` (an `IPv4Network`/etc. raises `ValueError` — it needs a host, not a network).
2. Resolves `hostname` to an IP if given (`localhost`/`127.0.0.1` short-circuits to `00:00:00:00:00:00`).
3. For remote IP/IPv6 lookups with `network_request=True`, tries to populate the ARP/NDP table — preferring `ArpFile` (fast file read) or `CtypesHost`/`ArpingHost` (real ARP request) over the fallback of firing a bare UDP packet at `settings.PORT` (default `55555`) to provoke the OS into populating its table.
4. Dispatches to `get_by_method("ip4"|"ip6"|"iface"|"default_iface", arg)`, falling back to default-interface detection when no argument is given.
5. Runs the raw result through `utils.clean_mac()` to normalize to lowercase colon-separated form (or `None`).

When adding support for a new command/platform quirk, add a new `Method` subclass near others of its `method_type`, add it to `METHODS`, and add a fixture-driven test in `tests/test_methods.py` — don't stretch an existing method's regex to cover an unrelated output format.

## Tests

- `tests/test_methods.py` — unit tests for individual `Method` subclasses and parsing helpers (e.g. `_parse_ifconfig`), driven by real command-output fixtures.
- `tests/test_getmac.py` — tests for `get_mac_address()` / `get_default_interface()` and the cache/fallback logic.
- `tests/test_utils.py` — tests for `getmac/utils.py` helpers.
- `tests/test_cli.py` — tests for `__main__.py`.
- `tests/test_packaging.py` — builds the sdist/wheel via `pdm build` and asserts on their contents (no dev files, tests excluded from wheel, etc.); this test is slower since it invokes a real build.
- `tests/samples/` — real captured output from platform commands, organized in subdirectories per OS/version (e.g. `ubuntu_18.04/`, `OSX/`, `freebsd11/`). Tests load these via the `get_sample` fixture in `tests/conftest.py` and mock `getmac.utils.popen`/`check_command` with `mocker.patch` (pytest-mock) rather than invoking real subprocesses.

When fixing a parsing bug for a specific platform/command version, add the raw command output as a new file under `tests/samples/<platform>/` (see "Sample collection" in `CONTRIBUTING.md`) and parametrize the existing test rather than hand-writing fixture strings inline.

## Compatibility constraints

- Must run on Python 3.8–3.14, CPython and PyPy — no C-extensions, stdlib only, no runtime dependencies.
- Prefer real type annotations (`def foo(x: str) -> Optional[str]:`) — this branch has already moved off the `# type:` comment style used on `main`.
- Settings/constants are accessed through the `settings` / `consts` / `gvars` singletons in `getmac/variables.py`, not as bare module attributes on `getmac.getmac` (that was the 0.9.x pattern).
