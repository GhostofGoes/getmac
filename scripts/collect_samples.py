#!/usr/bin/env python3
"""
Collect samples of command output for getmac's tests.

Runs the commands (and reads the files) that getmac uses on the current
platform, including the ones getmac falls back to on platforms it doesn't fully
support, plus some closely related commands that are useful when writing parsers.
The output of each one is saved to its own ``.out`` file in
``tests/samples/<platform>_<version>/`` (e.g. ``tests/samples/ubuntu_24.04/``),
or in ``./samples/<platform>_<version>/`` when the script isn't in a getmac
checkout (use ``--output-root`` to change this).
Exit codes and error output are logged to ``collect_samples.log`` in the same directory.

This only uses the Python standard library (Python 3.9+) and doesn't import getmac,
so it can be copied to and run on any machine with Python. The commands are kept in
sync with the methods in ``getmac/getmac.py`` by ``tests/test_collect_samples.py``.

Usage::

    python scripts/collect_samples.py --dry-run   # list what would be collected
    python scripts/collect_samples.py             # collect the samples
    python scripts/collect_samples.py --help      # all options

Some commands (e.g. ``arping``) only work when run as root/Administrator.

The samples contain real MAC addresses, IP addresses, and hostnames
from the system. Review and redact them before committing!
"""

# ruff: noqa: T201

import argparse
import ipaddress
import os
import platform
import re
import shlex
import shutil
import socket
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

LOG_NAME = "collect_samples.log"
REPO_SAMPLES_DIR = Path(__file__).resolve().parent.parent / "tests" / "samples"
SYS_CLASS_NET = "/sys/class/net"


@dataclass(frozen=True)
class Command:
    """
    A command to run. Arguments can contain the placeholders ``{iface}``
    (run once per network interface) and ``{ip}`` (run once per remote host IP).
    """

    argv: tuple[str, ...]
    name: str = ""  # Output file name (without ".out"), if the generated name isn't good
    network: bool = False  # If the command sends packets on the network
    merge_stderr: bool = False  # Save stderr with stdout, e.g. for usage messages


@dataclass(frozen=True)
class File:
    """A file to read. The path can contain the ``{iface}`` placeholder."""

    path: str


Spec = Union[Command, File]


def cmd(
    command_line: str, name: str = "", network: bool = False, merge_stderr: bool = False
) -> Command:
    return Command(tuple(shlex.split(command_line)), name, network, merge_stderr)


# Commands and files, grouped by the platforms they're found on. Anything that isn't
# installed is skipped, so it's fine for a group to include commands that only exist
# on some of its platforms. tests/test_collect_samples.py checks that every command
# and file used by a Method in getmac/getmac.py is included for that Method's platforms,
# and for the platforms where getmac falls back to the "other" Methods (see below).
GROUPS: dict[str, tuple[Spec, ...]] = {
    # Unix-like platforms
    "posix": (
        cmd("ifconfig"),
        cmd("ifconfig -a"),
        cmd("ifconfig {iface}"),
        cmd("arp -a"),
        cmd("arp -an"),
        cmd("arp {ip}"),
        cmd("arp -a {ip}"),
        cmd("arp -an {ip}"),
        cmd("netstat -i"),
        cmd("netstat -ia"),
        cmd("netstat -in"),
        cmd("netstat -r"),
        cmd("netstat -rn"),
        cmd("route -n"),
    ),
    # Linux, including Android and WSL
    "linux": (
        File("/proc/net/arp"),
        File("/proc/net/route"),
        File("/proc/net/ipv6_route"),
        File("/sys/class/net/{iface}/address"),
        cmd("ip link"),
        cmd("ip link list"),
        cmd("ip link show {iface}"),
        cmd("ip addr"),
        cmd("ip neighbor show"),
        cmd("ip neighbor show {ip}"),
        cmd("ip -6 neighbor show"),
        cmd("ip route list"),
        cmd("ip route list 0/0"),
        cmd("ip -6 route list"),
        cmd("ifconfig -v"),
        cmd("ifconfig -av"),
        cmd("netstat -iae"),
        # The output of an unknown option shows which arping this is (iputils or Habets)
        cmd("arping --help", merge_stderr=True),
        cmd("arping -f -c 1 {ip}", network=True),  # iputils and BusyBox
        cmd("arping -r -C 1 -c 1 {ip}", network=True),  # Habets
        cmd("lsb_release -a"),
    ),
    # BusyBox's versions of commands, which have their own output formats.
    # These are skipped if BusyBox isn't installed or doesn't include the command.
    "busybox": (
        cmd("busybox ifconfig"),
        cmd("busybox ifconfig -a"),
        cmd("busybox ifconfig {iface}"),
        cmd("busybox arp -a"),
        cmd("busybox arp -an"),
        cmd("busybox arp -a {ip}"),
        cmd("busybox ip link"),
        cmd("busybox ip link show {iface}"),
        cmd("busybox ip neigh show"),  # BusyBox doesn't accept "neighbor"
        cmd("busybox ip neigh show {ip}"),
        cmd("busybox ip route list 0/0"),
        cmd("busybox route -n"),
        cmd("busybox netstat -rn"),
        cmd("busybox arping --help", merge_stderr=True),
        cmd("busybox arping -f -c 1 {ip}", network=True),
    ),
    # Windows commands, run from inside WSL
    "wsl": (
        cmd("arp.exe -a"),
        cmd("arp.exe -a {ip}"),
        cmd("ipconfig.exe /all"),
        cmd("getmac.exe /NH /V"),
        cmd("netsh.exe int ipv4 show neigh"),
        cmd("netsh.exe int ipv6 show neigh"),
        cmd("route.exe print -4"),
    ),
    "windows": (
        cmd("arp.exe -a"),
        cmd("arp.exe -a {ip}"),
        cmd("getmac.exe /NH /V"),
        cmd("getmac.exe /NH /V /FO CSV"),  # codespell:ignore fo
        cmd("getmac.exe /V /FO CSV"),  # codespell:ignore fo
        cmd("ipconfig.exe /all"),
        cmd("wmic.exe nic get MACAddress,NetConnectionID /value"),
        cmd(
            'wmic.exe nic where "NetConnectionID = \'{iface}\'" get "MACAddress" /value',
            name="wmic_nic_where_NetConnectionID_{iface}_get_MACAddress",
        ),
        cmd("netsh.exe int ipv4 show neigh"),
        cmd("netsh.exe int ipv6 show neigh"),
        cmd("netsh.exe int ipv4 show route"),
        cmd("netsh.exe int ipv6 show route"),
        cmd("netsh.exe int show interface"),
        cmd("route.exe print -4"),
        cmd("route.exe print -6"),
        # WMIC is deprecated, this is the PowerShell replacement
        cmd(
            "powershell.exe -NoProfile -NonInteractive -Command "
            '"Get-NetAdapter | Format-List -Property Name,InterfaceDescription,Status,MacAddress"',
            name="powershell_Get-NetAdapter",
        ),
    ),
    "darwin": (
        cmd("networksetup -listallhardwareports"),
        cmd("networksetup -getmacaddress {iface}"),
        cmd("route get default"),
        cmd("route -n get default"),
        cmd("ndp -an"),
        cmd("arping --help", merge_stderr=True),
        cmd("arping -f -c 1 {ip}", network=True),
        cmd("arping -r -C 1 -c 1 {ip}", network=True),
        cmd("sw_vers"),
    ),
    # FreeBSD, OpenBSD, and NetBSD
    "bsd": (
        cmd("route get default"),
        cmd("route -n get default"),
        cmd("ndp -an"),
    ),
    "openbsd": (
        cmd("route -nq show -inet -gateway -priority 1"),
        cmd("route -n show"),
    ),
    "netbsd": (cmd("route -n show"),),
    # Solaris and illumos
    "sunos": (
        cmd("netstat -pn"),  # ARP table ("Net to Media Table")
        cmd("route -n get default"),
        cmd("dladm show-phys -m"),
        cmd("dladm show-linkprop -p mac-address"),
    ),
    "hpux": (
        cmd("lanscan"),
        cmd("lanscan -ai"),
        cmd("nwmgr"),
    ),
    # Commands used by getmac's "other" Methods. When getmac doesn't have any Methods
    # for a type of lookup on a platform, it falls back to the "other" Methods for it.
    # There's a group for each type of lookup, so platforms only get the ones they use.
    "other_ip": (  # MAC of a remote host
        cmd("arp {ip}"),
        cmd("arp -an"),
        cmd("arp -an {ip}"),
        cmd("arp -a"),
        cmd("arp -a {ip}"),
        cmd("ip neighbor show {ip}"),
    ),
    "other_iface": (  # MAC of an interface
        cmd("ifconfig"),
        cmd("ifconfig -a"),
        cmd("ifconfig -v"),
        cmd("ifconfig -av"),
        cmd("ifconfig {iface}"),
        cmd("netstat -iae"),
        cmd("ip link"),
        cmd("ip link show {iface}"),
    ),
    "other_default_iface": (  # Default interface
        cmd("route -n"),
        cmd("route get default"),
        cmd("ip route list 0/0"),
    ),
}

# The groups to collect for each platform. Platform names are the same as the ones
# used by getmac's Method.platforms, plus "netbsd". Unlike getmac, "wsl" is used for
# both WSL1 and WSL2, since both can run Windows commands. The "other_*" groups are
# for the types of lookups that getmac doesn't have Methods for on the platform, e.g.
# IPv6 hosts and the default interface on HP-UX, where "arp" and "route" exist.
PLATFORMS: dict[str, tuple[str, ...]] = {
    "linux": ("posix", "linux", "busybox"),
    "android": ("posix", "linux", "busybox", "other_ip", "other_default_iface"),
    "wsl": ("posix", "linux", "busybox", "wsl"),
    "windows": ("windows",),
    "darwin": ("posix", "darwin"),
    "freebsd": ("posix", "bsd"),
    "openbsd": ("posix", "bsd", "openbsd"),
    "netbsd": ("posix", "bsd", "netbsd", "other_ip", "other_iface", "other_default_iface"),
    "sunos": ("posix", "sunos", "other_iface", "other_default_iface"),
    "hp-ux": ("posix", "hpux", "other_ip", "other_default_iface"),
    # Unknown platform, try everything Unix-like (this has all of the "other_*" commands)
    "other": ("posix", "linux", "busybox", "bsd"),
}


def specs_for_platform(platform_name: str) -> list[Spec]:
    """All the commands and files to collect for a platform, without duplicates."""
    specs: list[Spec] = []
    for group in PLATFORMS[platform_name]:
        specs.extend(spec for spec in GROUPS[group] if spec not in specs)
    return specs


# --- Output file names ---

_UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9._,=+@-]+")


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _clean_name(text: str) -> str:
    return _UNSAFE_CHARS.sub("-", text)


def sample_filename(argv: tuple[str, ...], strip_exe: bool = False) -> str:
    """
    Name of the file to save a command's output to, following
    the naming of the existing samples, for example:

    - ``arp -a`` -> ``arp_-a.out``
    - ``arp 10.0.2.2`` -> ``arp_10-0-2-2.out``
    - ``ip route list 0/0`` -> ``ip_route_list_0slash0.out``
    - ``route.exe print -4`` -> ``route_print_-4.out`` (with ``strip_exe``)
    - ``ipconfig.exe /all`` -> ``ipconfig_-all.out`` (with ``strip_exe``)
    """
    command = argv[0]
    if strip_exe and command.lower().endswith(".exe"):
        command = command[:-4]

    parts = [_clean_name(command)]
    for arg in argv[1:]:
        if _is_ip(arg):
            arg = arg.replace(".", "-").replace(":", "-")
        elif arg.startswith("/") and len(arg) > 1:  # Windows option, e.g. "/all"
            arg = "-" + arg[1:]
        parts.append(_clean_name(arg.replace("/", "slash")))

    return "_".join(parts) + ".out"


def file_sample_filename(path: str) -> str:
    """
    Name of the file to save a file's contents to, e.g.
    ``/proc/net/arp`` -> ``cat_proc-net-arp.out``.
    """
    return "cat_" + _clean_name(path.strip("/").replace("/", "-")) + ".out"


# --- Platform detection ---


def is_android() -> bool:
    return (
        hasattr(sys, "getandroidapilevel")
        or "ANDROID_ROOT" in os.environ
        or "ANDROID_STORAGE" in os.environ
    )


def is_wsl(uname: platform.uname_result) -> bool:
    return uname.system == "Linux" and "microsoft" in (uname.release + uname.version).lower()


def is_wsl2(uname: platform.uname_result) -> bool:
    release = uname.release.lower()
    return is_wsl(uname) and ("wsl2" in release or "microsoft-standard" in release)


def detect_platform() -> str:
    """Name of the current platform, using the names in :data:`PLATFORMS`."""
    system = platform.system()
    if system == "Android":  # Python 3.13+ on Android (older versions say "Linux")
        return "android"
    if system == "Linux":
        if is_android():
            return "android"
        if is_wsl(platform.uname()):
            return "wsl"
        return "linux"

    names = {
        "Windows": "windows",
        "Darwin": "darwin",
        "FreeBSD": "freebsd",
        "OpenBSD": "openbsd",
        "NetBSD": "netbsd",
        "SunOS": "sunos",
        "HP-UX": "hp-ux",
    }
    return names.get(system, "other")


def read_os_release() -> dict[str, str]:
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            text = Path(path).read_text(errors="replace")
        except OSError:
            continue

        info = {}
        for line in text.splitlines():
            key, sep, value = line.partition("=")
            if sep and not key.startswith("#"):
                info[key.strip()] = value.strip().strip("\"'")
        return info

    return {}


def _windows_version(uname: platform.uname_result) -> str:
    release = uname.release
    build = uname.version.rpartition(".")[2]
    # Older Pythons report Windows 11 as "10"
    if release == "10" and build.isdigit() and int(build) >= 22000:
        release = "11"
    if "server" in release.lower():  # e.g. "2022Server"
        return "server_" + re.sub(r"(?i)server", "", release)
    return release


def default_dir_name(uname: platform.uname_result, os_release: dict[str, str]) -> str:
    """
    Name of the samples directory for this system, following the naming of the existing
    samples, e.g. ``ubuntu_18.04``, ``WSL2_kali_2023.1``, ``macos_10.12.6``, ``windows_10``.
    """
    system, release = uname.system, uname.release

    if system == "Windows":
        name = "windows_" + _windows_version(uname)
    elif system == "Darwin":
        version = platform.mac_ver()[0] or run_quiet(("sw_vers", "-productVersion"), 10)
        name = "macos_" + version.strip()
    elif system == "Android" or (system == "Linux" and is_android()):
        version = run_quiet(("getprop", "ro.build.version.release"), 10).strip()
        name = "android_" + version
    elif os_release.get("ID"):  # Linux distros, and some others (e.g. OpenIndiana)
        name = os_release["ID"]
        if os_release.get("VERSION_ID"):
            name += "_" + os_release["VERSION_ID"]
        if is_wsl(uname):
            name = ("WSL2_" if is_wsl2(uname) else "WSL_") + name
    elif system == "SunOS":
        name = "solaris_" + release.partition(".")[2]  # SunOS 5.10 is Solaris 10
    elif system == "HP-UX":
        name = "hpux_" + re.sub(r"^[A-Z]\.", "", release)  # "B.11.31" -> "11.31"
    elif system == "AIX":
        name = f"aix_{uname.version}.{release}"
    else:
        name = system.lower() + "_" + release.partition("-")[0]  # "13.2-RELEASE" -> "13.2"

    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_") or "unknown"


# --- Running commands ---


def command_search_path(windows: bool) -> str:
    """PATH used to find commands. Like getmac, this includes the sbin directories."""
    dirs = os.environ.get("PATH", os.defpath).split(os.pathsep)
    if not windows:
        dirs.extend(d for d in ("/sbin", "/usr/sbin") if d not in dirs)
    return os.pathsep.join(dirs)


def find_command(command: str, search_path: str) -> Optional[str]:
    """Full path of a command, or :obj:`None` if it isn't installed."""
    if command.lower().endswith(".exe"):
        # Skip Python "Scripts" folders, so a pip-installed getmac.exe
        # isn't used instead of the getmac.exe that comes with Windows.
        search_path = os.pathsep.join(
            d
            for d in search_path.split(os.pathsep)
            if os.path.basename(os.path.normpath(d)).lower() != "scripts"
        )
    return shutil.which(command, path=search_path)


@dataclass
class RunResult:
    returncode: Optional[int]  # None if the command couldn't be run or timed out
    stdout: bytes
    stderr: bytes
    error: str = ""


def run_command(
    argv: list[str], env: dict[str, str], timeout: float, merge_stderr: bool = False
) -> RunResult:
    try:
        proc = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,  # Some commands (e.g. wmic) hang waiting for input
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT if merge_stderr else subprocess.PIPE,
            env=env,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as ex:
        return RunResult(None, ex.stdout or b"", ex.stderr or b"", f"timed out after {timeout}s")
    except OSError as ex:
        return RunResult(None, b"", b"", f"couldn't run it: {ex}")
    return RunResult(proc.returncode, proc.stdout, proc.stderr or b"")


def read_bytes(path: str) -> Optional[bytes]:
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return None


def command_env() -> dict[str, str]:
    env = dict(os.environ)
    env["LC_ALL"] = "C"  # Same as getmac, so output is in English
    return env


def run_quiet(argv: tuple[str, ...], timeout: float) -> str:
    """Run a command and return its output, or an empty string if it failed."""
    path = find_command(argv[0], command_search_path(platform.system() == "Windows"))
    if not path:
        return ""
    result = run_command([path, *argv[1:]], command_env(), timeout)
    return result.stdout.decode(errors="replace") if result.returncode == 0 else ""


# --- Finding interfaces and the default gateway ---


def parse_interface_names(output: str) -> list[str]:
    """Interface names from ``ifconfig -a`` or ``netstat -in`` output."""
    names: list[str] = []
    for line in output.splitlines():
        if not line or line[0].isspace():
            continue
        name = line.split()[0].rstrip(":*")  # HP-UX marks down interfaces with a "*"
        if name not in ("Name", "Iface", "Kernel") and name not in names:
            names.append(name)
    return names


def parse_ipconfig(output: str) -> tuple[list[str], str, str]:
    """
    Get the adapter names from ``ipconfig /all`` output, and the name and gateway
    of the first adapter with an IPv4 default gateway.
    """
    adapters: list[str] = []
    default_iface = gateway = ""
    adapter = ""
    in_gateway = False

    for line in output.splitlines():
        if line and not line[0].isspace():
            match = re.match(r".*[ -]adapter (.+):$", line.strip(), re.IGNORECASE)
            adapter = match.group(1) if match else ""
            if adapter:
                adapters.append(adapter)
            in_gateway = False
            continue

        # The gateway can have multiple lines, e.g. an IPv6 address then an IPv4 address
        if "Default Gateway" in line:
            in_gateway = True
            value = line.partition(" : ")[2].strip()
        elif in_gateway and " : " not in line:
            value = line.strip()
        else:
            in_gateway = False
            continue

        if adapter and not gateway and _is_ip(value) and "." in value:
            default_iface, gateway = adapter, value

    return adapters, default_iface, gateway


def _gateway_ip(text: str) -> str:
    return text if _is_ip(text) and "." in text and text != "0.0.0.0" else ""  # noqa: S104


def parse_default_route(output: str, interfaces: list[str]) -> tuple[str, str]:
    """
    Get the default interface and IPv4 gateway from the output of
    ``ip route list 0/0``, ``route -n get default``, ``route -n``, or ``netstat -rn``.
    Anything not found is returned as an empty string.
    """
    iface = gateway = ""

    # "ip route": "default via 192.168.0.1 dev eth0 proto dhcp metric 100"
    # "route get": "  gateway: 192.168.0.1" and "interface: en0"
    match = re.search(r"\bdev\s+(\S+)|interface:\s*(\S+)", output)
    if match:
        iface = match.group(1) or match.group(2)
    match = re.search(r"\bvia\s+(\S+)|gateway:\s*(\S+)", output)
    if match:
        gateway = _gateway_ip(match.group(1) or match.group(2))

    # "route -n" and "netstat -rn": a table with a line for the default route
    # (HP-UX writes it as "default/0.0.0.0"). The column order varies,
    # so look for any IP and known interface in the line.
    for line in output.splitlines():
        fields = line.split()
        if fields and fields[0].partition("/")[0] in ("default", "0.0.0.0"):  # noqa: S104
            for field in fields[1:]:
                if not gateway:
                    gateway = _gateway_ip(field)
                if not iface and field in interfaces:
                    iface = field
            break

    return iface, gateway


def parse_proc_net_route(data: str) -> tuple[str, str]:
    """Get the default interface and gateway from ``/proc/net/route``."""
    for line in data.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 3 and fields[1] == "00000000":
            try:
                gateway = socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
            except (ValueError, struct.error):
                gateway = ""
            return fields[0], _gateway_ip(gateway)
    return "", ""


def find_interfaces(platform_name: str, timeout: float) -> list[str]:
    if platform_name == "windows":
        return parse_ipconfig(run_quiet(("ipconfig.exe", "/all"), timeout))[0]

    # Interfaces are directories (symlinks to them), but there can be files
    # too, e.g. "bonding_masters" when the bonding driver is loaded
    try:
        names = os.listdir(SYS_CLASS_NET)
        return sorted(n for n in names if os.path.isdir(os.path.join(SYS_CLASS_NET, n)))
    except OSError:
        pass
    try:
        return [name for _, name in socket.if_nameindex()]
    except (OSError, AttributeError):  # Not available on all platforms
        pass
    return parse_interface_names(
        run_quiet(("ifconfig", "-a"), timeout) or run_quiet(("netstat", "-in"), timeout)
    )


def find_default_route(
    platform_name: str, interfaces: list[str], timeout: float
) -> tuple[str, str]:
    """
    Find the default interface and IPv4 gateway, mostly the same ways that getmac's
    ``DefaultIface*`` methods do. Anything not found is returned as an empty string.
    """
    if platform_name == "windows":
        return parse_ipconfig(run_quiet(("ipconfig.exe", "/all"), timeout))[1:]

    data = read_bytes("/proc/net/route")
    iface, gateway = parse_proc_net_route(data.decode(errors="replace")) if data else ("", "")

    for argv in (
        ("ip", "route", "list", "0/0"),
        ("route", "-n", "get", "default"),
        ("route", "-n"),
        ("netstat", "-rn"),
    ):
        if iface and gateway:
            break
        found_iface, found_gateway = parse_default_route(run_quiet(argv, timeout), interfaces)
        iface = iface or found_iface
        gateway = gateway or found_gateway

    return iface, gateway


# --- Collecting samples ---


@dataclass
class Sample:
    """A command to run or a file to read, and what happened when it was collected."""

    label: str  # Command line or file path
    filename: str = ""
    argv: tuple[str, ...] = ()
    path: str = ""
    network: bool = False
    merge_stderr: bool = False
    executable: str = ""  # Full path of the command, once it's been found
    status: str = ""
    detail: str = ""
    stderr: str = ""


def _label(argv: tuple[str, ...]) -> str:
    return " ".join(f'"{arg}"' if not arg or " " in arg else arg for arg in argv)


def _fill(text: str, iface: str, ip: str) -> str:
    return text.replace("{iface}", iface).replace("{ip}", ip)


def plan_samples(
    specs: list[Spec], interfaces: list[str], ips: list[str], strip_exe: bool
) -> list[Sample]:
    """Expand the placeholders in the commands and files into a list of samples to collect."""
    samples: list[Sample] = []
    filenames: set[str] = set()

    for spec in specs:
        template = _label(spec.argv) if isinstance(spec, Command) else spec.path
        uses_iface = "{iface}" in template
        uses_ip = "{ip}" in template

        if uses_iface and not interfaces:
            samples.append(Sample(template, status="skipped", detail="no interfaces found"))
            continue
        if uses_ip and not ips:
            samples.append(Sample(template, status="skipped", detail="no remote IP to look up"))
            continue

        for iface in interfaces if uses_iface else [""]:
            for ip in ips if uses_ip else [""]:
                if isinstance(spec, Command):
                    argv = tuple(_fill(arg, iface, ip) for arg in spec.argv)
                    if spec.name:
                        filename = _clean_name(_fill(spec.name, iface, ip)) + ".out"
                    else:
                        filename = sample_filename(argv, strip_exe)
                    sample = Sample(
                        _label(argv),
                        filename,
                        argv=argv,
                        network=spec.network,
                        merge_stderr=spec.merge_stderr,
                    )
                else:
                    path = _fill(spec.path, iface, ip)
                    sample = Sample(path, file_sample_filename(path), path=path)

                if sample.filename not in filenames:
                    filenames.add(sample.filename)
                    samples.append(sample)

    return samples


class Collector:
    """Checks, runs, and saves the samples."""

    def __init__(self, out_dir: Path, timeout: float, windows: bool) -> None:
        self.out_dir = out_dir
        self.timeout = timeout
        self.search_path = command_search_path(windows)
        self.env = command_env()
        self._busybox_applets: Optional[set[str]] = None

    def _find_command(self, sample: Sample) -> bool:
        sample.executable = find_command(sample.argv[0], self.search_path) or ""
        if sample.executable and sample.argv[0] == "busybox" and len(sample.argv) > 1:
            if self._busybox_applets is None:
                result = run_command([sample.executable, "--list"], self.env, self.timeout)
                output = result.stdout.decode(errors="replace")
                self._busybox_applets = set(output.split()) if result.returncode == 0 else set()
            # Old versions of BusyBox don't have "--list", so assume the command is there
            return not self._busybox_applets or sample.argv[1] in self._busybox_applets
        return bool(sample.executable)

    def check(self, sample: Sample, force: bool, network: bool) -> None:
        """
        Find the sample's command, and check that the sample can and should be
        collected. If it can't, the sample's status is set to the reason why.
        """
        if sample.status:  # Already skipped while planning
            return
        if sample.network and not network:
            sample.status, sample.detail = "skipped", "sends network traffic (--no-network)"
        elif sample.argv and not self._find_command(sample):
            sample.status = "not installed"
        elif sample.path and not os.access(sample.path, os.R_OK):
            sample.status = "not found"
        elif (self.out_dir / sample.filename).exists() and not force:
            sample.status = "exists"

    def collect(self, sample: Sample) -> None:
        if sample.argv:
            start = time.monotonic()
            result = run_command(
                [sample.executable, *sample.argv[1:]],
                self.env,
                self.timeout,
                sample.merge_stderr,
            )
            seconds = time.monotonic() - start
            output = result.stdout
            sample.stderr = result.stderr.decode(errors="replace").strip()

            if result.returncode is None:  # Couldn't run it, or it timed out
                sample.status, sample.detail = "failed", result.error
                if output:
                    # Output from a command that timed out is incomplete. Saving it would
                    # make it look like a real sample, and stop it being run again.
                    sample.detail += ", partial output not saved"
                    output = b""
            elif result.returncode != 0:
                sample.status = "failed"
                sample.detail = f"exit code {result.returncode}"
            else:
                sample.status = "saved" if output else "no output"
                sample.detail = f"{seconds:.2f}s"
        else:
            data = read_bytes(sample.path)
            output = data or b""
            if data is None:
                sample.status, sample.detail = "failed", "couldn't read the file"
            else:
                sample.status = "saved" if output else "no output"

        # Save output of failed commands too, it's useful for handling errors
        if output:
            self.out_dir.mkdir(parents=True, exist_ok=True)
            # Write the raw bytes, so Windows line endings ("\r\n") are kept
            (self.out_dir / sample.filename).write_bytes(output)
            if sample.status == "failed":
                sample.detail += ", output saved"


# Statuses in the order they're shown in the summary
_STATUSES = (
    "saved",
    "no output",
    "failed",
    "would run",
    "would read",
    "exists",
    "not installed",
    "not found",
    "skipped",
    "not run",
)
_ARROW_STATUSES = ("saved", "would run", "would read", "exists")


def _print_sample(sample: Sample) -> None:
    arrow = f" -> {sample.filename}" if sample.status in _ARROW_STATUSES else ""
    detail = f"  ({sample.detail})" if sample.detail else ""
    print(f"  {sample.status:>13}  {sample.label}{arrow}{detail}")
    if sample.status == "failed" and sample.stderr:
        print(f"  {'':>13}    {sample.stderr.splitlines()[0][:150]}")


def write_log(log_path: Path, header: list[str], samples: list[Sample]) -> None:
    """Add the results of this run to the end of the log."""
    lines = [f"=== {line}" for line in header]
    for sample in samples:
        saved = f" -> {sample.filename}" if sample.status == "saved" else ""
        detail = f" ({sample.detail})" if sample.detail else ""
        lines.append(f"[{sample.status}] {sample.label}{saved}{detail}")
        lines.extend(f"    stderr: {line}" for line in sample.stderr.splitlines()[:20])

    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n\n")


def wrote_files(samples: list[Sample]) -> bool:
    """If any samples were collected, in which case the log (and maybe samples) was saved."""
    return any(s.status in ("saved", "no output", "failed") for s in samples)


def print_summary(samples: list[Sample], out_dir: Path, dry_run: bool) -> None:
    counts = {status: sum(s.status == status for s in samples) for status in _STATUSES}
    print("\nSummary: " + ", ".join(f"{n} {status}" for status, n in counts.items() if n))

    failed = [s for s in samples if s.status == "failed"]
    if failed:
        print("\nFailed (exit codes and error output are in the log):")
        for sample in failed:
            print(f"  {sample.label}  ({sample.detail})")

    if dry_run:
        print(
            "\nDry run: no samples were collected or saved. Some read-only commands may\n"
            "still have been run to find the interfaces, the default gateway, and the\n"
            "commands BusyBox has (e.g. 'ip route list 0/0', 'busybox --list',\n"
            "'ipconfig.exe /all')."
        )

    if not wrote_files(samples):
        return  # Nothing to review

    print(f"\nSaved to: {out_dir}")
    print(f"Log: {out_dir / LOG_NAME}")
    print(
        "\n"
        "!!! IMPORTANT !!!\n"
        "The samples contain real MAC addresses, IP addresses, and hostnames from\n"
        "this system. Review every file (including the log) in:\n"
        f"    {out_dir}\n"
        "and replace anything you don't want to make public BEFORE committing.\n"
        "Use the same replacement everywhere a value appears, so the samples\n"
        "stay consistent with each other."
    )


def build_parser() -> argparse.ArgumentParser:
    default_root = REPO_SAMPLES_DIR if REPO_SAMPLES_DIR.is_dir() else Path("samples")
    parser = argparse.ArgumentParser(
        description=(
            "Collect samples of the output of the commands getmac uses on this platform, "
            "and save them to <output-root>/<platform>_<version>/."
        ),
        epilog=(
            "The samples contain real MAC addresses, IP addresses, and hostnames. "
            "Review and redact them before committing!"
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="list the samples that would be collected, without collecting or saving anything. "
        "A few read-only commands (e.g. 'ip route list 0/0', 'busybox --list') may still be "
        "run to find the interfaces, the default gateway, and the commands BusyBox has",
    )
    parser.add_argument("-f", "--force", action="store_true", help="overwrite existing samples")
    parser.add_argument(
        "-o",
        "--output-root",
        type=Path,
        default=default_root,
        metavar="DIR",
        help="directory to create the samples directory in (default: %(default)s)",
    )
    parser.add_argument(
        "-n",
        "--name",
        help="name of the samples directory (default: the detected platform and version, "
        "e.g. 'ubuntu_24.04')",
    )
    parser.add_argument(
        "-p",
        "--platform",
        choices=sorted(PLATFORMS),
        help="collect the commands for this platform instead of the detected one",
    )
    parser.add_argument(
        "-i",
        "--interface",
        action="append",
        default=[],
        metavar="IFACE",
        help="interface to run interface commands for, e.g. 'ifconfig IFACE'. Can be used "
        "multiple times (default: all interfaces)",
    )
    parser.add_argument(
        "--default-interface-only",
        action="store_true",
        help="only run interface commands for the default interface",
    )
    parser.add_argument(
        "--ip",
        action="append",
        default=[],
        help="IP address of a remote host to look up, e.g. 'arp -a IP'. Can be used "
        "multiple times (default: the default gateway)",
    )
    parser.add_argument(
        "--no-network",
        action="store_true",
        help="skip commands that send packets on the network (arping)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=15.0,
        metavar="SECONDS",
        help="how long to wait for each command (default: %(default)s)",
    )
    return parser


def main(args: Optional[list[str]] = None) -> int:
    opts = build_parser().parse_args(args)

    platform_name = opts.platform or detect_platform()
    uname = platform.uname()
    os_release = read_os_release()
    out_dir = opts.output_root / (opts.name or default_dir_name(uname, os_release))

    interfaces = find_interfaces(platform_name, opts.timeout)
    default_iface, gateway = find_default_route(platform_name, interfaces, opts.timeout)
    if opts.interface:
        interfaces = opts.interface
    elif opts.default_interface_only and default_iface:
        interfaces = [default_iface]
    elif default_iface in interfaces:  # Do the default interface first
        interfaces = [default_iface] + [i for i in interfaces if i != default_iface]
    ips = opts.ip or ([gateway] if gateway else [])

    header = [
        f"collect_samples.py run at {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"Platform: {platform_name} ({uname.system} {uname.release} {uname.version})",
        f"OS: {os_release.get('PRETTY_NAME') or platform.platform()}",
        f"Python: {platform.python_version()}",
        f"Default interface: {default_iface or '(not found)'}",
        f"Default gateway: {gateway or '(not found)'}",
        f"Interfaces: {', '.join(interfaces) or '(none found)'}",
        f"Remote IPs: {', '.join(ips) or '(none)'}",
    ]
    print("\n".join(header[1:]))
    print(f"Output directory: {out_dir}\n")

    samples = plan_samples(
        specs_for_platform(platform_name), interfaces, ips, strip_exe=platform_name == "windows"
    )
    collector = Collector(out_dir, opts.timeout, windows=platform_name == "windows")
    for sample in samples:
        collector.check(sample, opts.force, not opts.no_network)

    missing = sorted({s.argv[0] for s in samples if s.status == "not installed"})
    if missing:
        print(f"Not installed, skipping: {', '.join(missing)}\n")

    try:
        for sample in samples:
            if not sample.status:  # Not skipped by check()
                if opts.dry_run:
                    sample.status = "would run" if sample.argv else "would read"
                else:
                    collector.collect(sample)
            if sample.status != "not installed":
                _print_sample(sample)
    except KeyboardInterrupt:
        print("\nInterrupted!")
        for sample in samples:
            sample.status = sample.status or "not run"

    if wrote_files(samples):
        write_log(out_dir / LOG_NAME, header, samples)

    print_summary(samples, out_dir, opts.dry_run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
