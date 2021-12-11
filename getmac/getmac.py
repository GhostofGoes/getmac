# -*- coding: utf-8 -*-
# http://multivax.com/last_question.html

"""Get the MAC address of remote hosts or network interfaces.

It provides a platform-independent interface to get the MAC addresses of:

- System network interfaces (by interface name)
- Remote hosts on the local network (by IPv4/IPv6 address or hostname)

It provides one function: ``get_mac_address()``

.. code-block:: python
   :caption: Examples

    from getmac import get_mac_address
    eth_mac = get_mac_address(interface="eth0")
    win_mac = get_mac_address(interface="Ethernet 3")
    ip_mac = get_mac_address(ip="192.168.0.1")
    ip6_mac = get_mac_address(ip6="::1")
    host_mac = get_mac_address(hostname="localhost")
    updated_mac = get_mac_address(ip="10.0.0.1", network_request=True)

"""
import ctypes
import logging
import os
import platform
import re
import shlex
import socket
import struct
import sys
import traceback
import warnings
from subprocess import CalledProcessError, check_output

try:  # Python 3
    from subprocess import DEVNULL  # type: ignore
except ImportError:  # Python 2
    DEVNULL = open(os.devnull, "wb")  # type: ignore

# Used for mypy (a data type analysis tool)
# If you're copying the code, this section can be safely removed
try:
    from typing import TYPE_CHECKING

    if TYPE_CHECKING:
        from typing import Dict, List, Optional, Set, Tuple, Type, Union
except ImportError:
    pass

# Configure logging
log = logging.getLogger("getmac")  # type: logging.Logger
if not log.handlers:
    log.addHandler(logging.NullHandler())

__version__ = "0.9.0a0"

PY2 = sys.version_info[0] == 2  # type: bool

# Configurable settings
DEBUG = 0  # type: int
PORT = 55555  # type: int

# Monkeypatch shutil.which for python 2.7 (TODO(python3): remove this hack)
if PY2:
    from .shutilwhich import which
else:
    from shutil import which

# Platform identifiers
_SYST = platform.system()  # type: str
if _SYST == "Java":
    try:
        import java.lang

        _SYST = str(java.lang.System.getProperty("os.name"))
    except ImportError:
        log.critical("Can't determine OS: couldn't import java.lang on Jython")
WINDOWS = _SYST == "Windows"  # type: bool
DARWIN = _SYST == "Darwin"  # type: bool
OPENBSD = _SYST == "OpenBSD"  # type: bool
FREEBSD = _SYST == "FreeBSD"  # type: bool
# Not including Darwin for now
BSD = OPENBSD or FREEBSD  # type: bool
# Windows Subsystem for Linux (WSL)
WSL = False  # type: bool
LINUX = False  # type: bool
if _SYST == "Linux":
    if "Microsoft" in platform.version():
        WSL = True
    else:
        LINUX = True

# Generic platform identifier used for filtering methods
PLATFORM = _SYST.lower()  # type: str
if PLATFORM == "linux" and "Microsoft" in platform.version():
    PLATFORM = "wsl"

# Get and cache the configured system PATH on import
# The process environment does not change after a process is started
PATH = os.environ.get("PATH", os.defpath).split(os.pathsep)  # type: List[str]
if not WINDOWS:
    PATH.extend(("/sbin", "/usr/sbin"))
else:
    # TODO: Prevent edge case on Windows where our script "getmac.exe"
    #   gets added to the path ahead of the actual Windows getmac.exe
    #   This just handles case where it's in a virtualenv, won't work /w global scripts
    PATH = [p for p in PATH if "\\getmac\\Scripts" not in p]
# Build the str after modifications are made
PATH_STR = os.pathsep.join(PATH)  # type: str

# Use a copy of the environment so we don't
# modify the process's current environment.
ENV = dict(os.environ)  # type: Dict[str, str]
ENV["LC_ALL"] = "C"  # Ensure ASCII output so we parse correctly

# Constants
IP4 = 0
IP6 = 1
INTERFACE = 2
HOSTNAME = 3

MAC_RE_COLON = r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"
MAC_RE_DASH = r"([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})"
# On OSX, some MACs in arp output may have a single digit instead of two
# Examples: "18:4f:32:5a:64:5", "14:cc:20:1a:99:0"
MAC_RE_DARWIN = r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})"

# Ensure we only log the Python 2 warning once
WARNED_UNSUPPORTED_PYTHONS = False

# Cache of commands that have been checked for existence by check_command()
CHECK_COMMAND_CACHE = {}  # type: Dict[str, bool]


def check_command(command):
    # type: (str) -> bool
    if command not in CHECK_COMMAND_CACHE:
        CHECK_COMMAND_CACHE[command] = bool(which(command, path=PATH_STR))
    return CHECK_COMMAND_CACHE[command]


def check_path(filepath):
    # type: (str) -> bool
    return os.path.exists(filepath) and os.access(filepath, os.R_OK)


def _clean_mac(mac):
    # type: (Optional[str]) -> Optional[str]
    """Check and format a string result to be lowercase colon-separated MAC."""
    if mac is None:
        return None

    # Handle cases where it's bytes (which are the same as str in PY2)
    mac = str(mac)
    if not PY2:  # Strip bytestring conversion artifacts
        # TODO(python3): check for bytes and decode instead of this weird hack
        for garbage_string in ["b'", "'", "\\n", "\\r"]:
            mac = mac.replace(garbage_string, "")

    # Remove trailing whitespace, make lowercase, remove spaces,
    # and replace dashes '-' with colons ':'.
    mac = mac.strip().lower().replace(" ", "").replace("-", ":")

    # Fix cases where there are no colons
    if ":" not in mac and len(mac) == 12:
        log.debug("Adding colons to MAC %s", mac)
        mac = ":".join(mac[i : i + 2] for i in range(0, len(mac), 2))

    # Pad single-character octets with a leading zero (e.g. Darwin's ARP output)
    elif len(mac) < 17:
        log.debug(
            "Length of MAC %s is %d, padding single-character octets with zeros",
            mac,
            len(mac),
        )
        parts = mac.split(":")
        new_mac = []
        for part in parts:
            if len(part) == 1:
                new_mac.append("0" + part)
            else:
                new_mac.append(part)
        mac = ":".join(new_mac)

    # MAC address should ALWAYS be 17 characters before being returned
    if len(mac) != 17:
        log.warning("MAC address %s is not 17 characters long!", mac)
        mac = None
    elif mac.count(":") != 5:
        log.warning("MAC address %s is missing colon (':') characters", mac)
        mac = None
    return mac


def _read_file(filepath):
    # type: (str) -> Optional[str]
    try:
        with open(filepath) as f:
            return f.read()
    # This is IOError on Python 2.7
    except (OSError, IOError):  # noqa: B014
        log.debug("Could not find file: '%s'", filepath)
        return None


def _search(regex, text, group_index=0, flags=0):
    # type: (str, str, int, int) -> Optional[str]
    match = re.search(regex, text, flags)
    if match:
        return match.groups()[group_index]
    return None


def _popen(command, args):
    # type: (str, str) -> str
    for directory in PATH:
        executable = os.path.join(directory, command)
        if (
            os.path.exists(executable)
            and os.access(executable, os.F_OK | os.X_OK)
            and not os.path.isdir(executable)
        ):
            break
    else:
        executable = command
    if DEBUG >= 3:
        log.debug("Running: '%s %s'", executable, args)
    return _call_proc(executable, args)


def _call_proc(executable, args):
    # type: (str, str) -> str
    if WINDOWS:
        cmd = executable + " " + args  # type: ignore
    else:
        cmd = [executable] + shlex.split(args)  # type: ignore
    output = check_output(cmd, stderr=DEVNULL, env=ENV)
    if DEBUG >= 4:
        log.debug("Output from '%s' command: %s", executable, str(output))
    if not PY2 and isinstance(output, bytes):
        return str(output, "utf-8")
    else:
        return str(output)


def _uuid_convert(mac):
    # type: (int) -> str
    return ":".join(("%012X" % mac)[i : i + 2] for i in range(0, 12, 2))


def _fetch_ip_using_dns():
    # type: () -> str
    """Determines the IP address of the default network interface.

    Sends a UDP packet to Cloudflare's DNS (``1.1.1.1``), which should go through
    the default interface. This populates the source address of the socket,
    which we then inspect and return.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("1.1.1.1", 53))
    ip = s.getsockname()[0]
    s.close()  # NOTE: sockets don't have context manager in 2.7 :(
    return ip


# TODO: cache method checks (maybe move this to 1.1.0 release?)
#   This string simply has the names of methods
#   Save to: file (location configurable via environment variable or option)
#   Read from: file, environment variable, file pointed to by environment variable
#   Add a flag to control this behavior and location of the cache
#   Document the behavior

# TODO: MAC -> IP. "to_find='mac'"? (create GitHub issue?)

# Regex resources:
#   https://pythex.org/
#   https://regex101.com/


class Method:
    # VALUES: {linux, windows, bsd, darwin, freebsd, openbsd, wsl, other}
    # TODO: platform versions/releases, e.g. Windows 7 vs 10, Ubuntu 12 vs 20
    platforms = set()  # type: Set[str]
    # VALUES: {ip, ip4, ip6, iface, default_iface}
    method_type = ""  # type: str
    # If the method makes a network request as part of the check
    net_request = False  # type: bool
    # (TODO) If current system supports this method. Dynamically set at runtime?
    #   This would let each method do more fine-grained version checking
    supported = False  # type: bool
    # Marks the method as unable to be used, e.g. if there was a runtime
    # error indicating the method won't work on the current platform.
    unusable = False  # type: bool

    def test(self):  # type: () -> bool
        """Low-impact test that the method is feasible, e.g. command exists."""
        pass  # pragma: no cover

    # TODO: automatically clean MAC on return
    def get(self, arg):  # type: (str) -> Optional[str]
        """Core logic of the method that performs the lookup.

        .. warning::
           If the method itself fails to function an exception will be raised!
           (for instance, if some command arguments are invalid, or there's an
           internal error with the command, or a bug in the code).

        Args:
            arg (str): What the method should get, such as an IP address
                or interface name. In the case of default_iface methods,
                this is not used and defaults to an empty string.

        Returns:
            Lowercase colon-separated MAC address, or None if one could
            not be found.
        """
        pass  # pragma: no cover

    @classmethod
    def __str__(cls):  # type: () -> str
        return cls.__name__


class ArpFile(Method):
    platforms = {"linux"}
    method_type = "ip"
    _path = os.environ.get("ARP_PATH", "/proc/net/arp")  # type: str

    def test(self):  # type: () -> bool
        return check_path(self._path)

    def get(self, arg):  # type: (str) -> Optional[str]
        data = _read_file(self._path)
        if data is not None and len(data) > 1:
            # Need a space, otherwise a search for 192.168.16.2
            # will match 192.168.16.254 if it comes first!
            return _search(re.escape(arg) + r" .+" + MAC_RE_COLON, data)
        return None


class SysIfaceFile(Method):
    platforms = {"linux", "wsl"}
    method_type = "iface"
    _path = "/sys/class/net/"  # type: str

    def test(self):  # type: () -> bool
        # TODO: imperfect, but should work well enough
        return check_path(self._path)

    def get(self, arg):  # type: (str) -> Optional[str]
        data = _read_file(self._path + arg + "/address")
        # Sometimes this can be empty or a single newline character
        return None if data is not None and len(data) < 17 else data


class UuidLanscan(Method):
    platforms = {"other"}
    method_type = "iface"

    def test(self):  # type: () -> bool
        try:
            from uuid import _find_mac  # noqa: T484

            return check_command("lanscan")
        except Exception:
            return False

    def get(self, arg):  # type: (str) -> Optional[str]
        from uuid import _find_mac  # type: ignore

        if not PY2:
            arg = bytes(arg, "utf-8")  # type: ignore
        mac = _find_mac("lanscan", "-ai", [arg], lambda i: 0)
        if mac:
            return _uuid_convert(mac)
        return None


class CtypesHost(Method):
    platforms = {"windows"}
    method_type = "ip4"
    net_request = True

    def test(self):  # type: () -> bool
        try:
            return ctypes.windll.wsock32.inet_addr(b"127.0.0.1") > 0  # noqa: T484
        except Exception:
            return False

    def get(self, arg):  # type: (str) -> Optional[str]
        if not PY2:  # Convert to bytes on Python 3+ (Fixes GitHub issue #7)
            arg = arg.encode()  # type: ignore
        try:
            inetaddr = ctypes.windll.wsock32.inet_addr(arg)  # type: ignore
            if inetaddr in (0, -1):
                raise Exception
        except Exception:
            # TODO: this assumes failure is due to arg being a hostname
            #   We should be explicit about only accepting ipv4 addresses
            #   and handle any hostname resolution in calling code
            hostip = socket.gethostbyname(arg)
            inetaddr = ctypes.windll.wsock32.inet_addr(hostip)  # type: ignore

        buffer = ctypes.c_buffer(6)
        addlen = ctypes.c_ulong(ctypes.sizeof(buffer))

        send_arp = ctypes.windll.Iphlpapi.SendARP  # type: ignore
        if send_arp(inetaddr, 0, ctypes.byref(buffer), ctypes.byref(addlen)) != 0:
            return None

        # Convert binary data into a string.
        macaddr = ""
        for intval in struct.unpack("BBBBBB", buffer):  # type: ignore
            if intval > 15:
                replacestr = "0x"
            else:
                replacestr = "x"
            macaddr = "".join([macaddr, hex(intval).replace(replacestr, "")])
        return macaddr


class ArpingHost(Method):
    """Use ``arping`` command to determine the MAC of a host.

    Supports two variants of ``arping``

    - "habets" arping by Thomas Habets
        (`GitHub <https://github.com/ThomasHabets/arping>`__)
    - "iputils" arping, from the ``iputils-arping``
        `package <https://packages.debian.org/sid/iputils-arping>`__
    """

    platforms = {"linux", "darwin"}
    method_type = "ip4"
    net_request = True
    _checked_type = False  # type: bool
    _is_iputils = False  # type: bool
    _habets = "-r -C 1 -c 1 %s"
    _iputils = "-f -c 1 %s"

    def test(self):  # type: () -> bool
        return check_command("arping")

    def get(self, arg):  # type: (str) -> Optional[str]
        # First execution we check which command it is. Adds a bit of time.
        # TODO: is there a more efficient way to do this check than running a command?
        #   maybe try to just run it, if we get unlucky then mark as the proper type,
        #   then try again with the proper type. e.g. try it as iputils, if get
        #   return code of 2, then mark it as habets and retry with habets.
        #   slightly more efficient than running it, then running it again.
        #   the performance impact is only on the first request of a run, but
        #   this is a common case for CLI programs and other one-off sorts of things.
        if not self._checked_type:
            try:
                _popen("arping", "--ridiculous-garbage-string")
            except CalledProcessError as ex:
                # iputils-arping returns 2 on invalid syntax (and other errors)
                if ex.returncode == 2:
                    self._is_iputils = True
                # habets returns 1 on invalid syntax. no need to check,
                # we already threw an exception so mark as checked.
                self._checked_type = True
        try:
            if self._is_iputils:
                command_output = _popen("arping", "-f -c 1 %s" % arg)
                if command_output:
                    return _search(
                        r" from %s \[(%s)\]" % (re.escape(arg), MAC_RE_COLON),
                        command_output,
                    )
            else:
                command_output = _popen("arping", "-r -C 1 -c 1 %s" % arg)
                if command_output:
                    return command_output.strip()
        except CalledProcessError:
            # TODO: verify return code isn't 2 for iputils? need to experiment
            #   with this some more to have a more reliable check.
            pass
        return None


class FcntlIface(Method):
    platforms = {"linux", "wsl"}
    method_type = "iface"

    def test(self):  # type: () -> bool
        try:
            import fcntl

            return True
        except Exception:  # Broad except to handle unknown effects
            return False

    def get(self, arg):  # type: (str) -> Optional[str]
        import fcntl

        if not PY2:
            arg = arg.encode()  # type: ignore
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # 0x8927 = SIOCGIFADDR
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack("256s", arg[:15]))
        if PY2:
            return ":".join(["%02x" % ord(char) for char in info[18:24]])
        else:
            return ":".join(["%02x" % ord(chr(char)) for char in info[18:24]])


# TODO(py3): do we want to keep this around? It calls 3 commands and is
#   quite inefficient. We should just take the methods and use directly.
class UuidArpGetNode(Method):
    platforms = {"linux", "darwin"}
    method_type = "ip"

    def test(self):  # type: () -> bool
        try:
            from uuid import _arp_getnode  # type: ignore

            return True
        except Exception:
            return False

    def get(self, arg):  # type: (str) -> Optional[str]
        from uuid import _arp_getnode  # type: ignore

        backup = socket.gethostbyname
        try:
            socket.gethostbyname = lambda x: arg  # noqa: F841
            mac1 = _arp_getnode()
            if mac1 is not None:
                mac1 = _uuid_convert(mac1)
                mac2 = _arp_getnode()
                mac2 = _uuid_convert(mac2)
                if mac1 == mac2:
                    return mac1
        except Exception:
            raise
        finally:
            socket.gethostbyname = backup
        return None


class GetmacExe(Method):
    platforms = {"windows"}
    method_type = "iface"
    _regexes = [
        # Connection Name
        (r"\r\n", r".*" + MAC_RE_DASH + r".*\r\n"),
        # Network Adapter (the human-readable name)
        (r"\r\n.*", r".*" + MAC_RE_DASH + r".*\r\n"),
    ]  # type: List[Tuple[str, str]]
    _champ = ()  # type: Union[tuple, Tuple[str, str]]

    def test(self):  # type: () -> bool
        return check_command("getmac.exe")

    def get(self, arg):  # type: (str) -> Optional[str]
        command_output = _popen("getmac.exe", "/NH /V")
        if self._champ:
            return _search(self._champ[0] + arg + self._champ[1], command_output)
        for pair in self._regexes:
            result = _search(pair[0] + arg + pair[1], command_output)
            if result:
                self._champ = pair
                return result
        return None


class IpconfigExe(Method):
    platforms = {"windows"}
    method_type = "iface"
    _regex = (
        r"(?:\n?[^\n]*){1,8}Physical Address[ .:]+" + MAC_RE_DASH + r"\r\n"
    )  # type: str

    def test(self):  # type: () -> bool
        return check_command("ipconfig.exe")

    def get(self, arg):  # type: (str) -> Optional[str]
        return _search(arg + self._regex, _popen("ipconfig.exe", "/all"))


class WmicExe(Method):
    platforms = {"windows"}
    method_type = "iface"

    def test(self):  # type: () -> bool
        return check_command("wmic.exe")

    def get(self, arg):  # type: (str) -> Optional[str]
        command_output = _popen(
            "wmic.exe",
            'nic where "NetConnectionID = \'%s\'" get "MACAddress" /value' % arg,
        )
        # Negative: "No Instance(s) Available"
        # Positive: "MACAddress=00:FF:E7:78:95:A0"
        # Note: .partition() always returns 3 parts,
        # therefore it won't cause an IndexError
        return command_output.strip().partition("=")[2]


class ArpExe(Method):
    platforms = {"windows", "wsl"}
    method_type = "ip"

    def test(self):  # type: () -> bool
        return check_command("arp.exe")

    def get(self, arg):  # type: (str) -> Optional[str]
        return _search(MAC_RE_DASH, _popen("arp.exe", "-a %s" % arg))


class DarwinNetworksetup(Method):
    # TODO: obtain output sample of networksetup for use in unit tests
    platforms = {"darwin"}
    method_type = "iface"

    def test(self):  # type: () -> bool
        return check_command("networksetup")

    def get(self, arg):  # type: (str) -> Optional[str]
        command_output = _popen("networksetup", "-getmacaddress %s" % arg)
        return _search(MAC_RE_COLON, command_output)


class ArpFreebsd(Method):
    platforms = {"freebsd"}
    method_type = "ip"

    def test(self):  # type: () -> bool
        return check_command("arp")

    def get(self, arg):  # type: (str) -> Optional[str]
        regex = r"\(" + re.escape(arg) + r"\)\s+at\s+" + MAC_RE_COLON
        return _search(regex, _popen("arp", arg))


class ArpOpenbsd(Method):
    platforms = {"openbsd"}
    method_type = "ip"
    _regex = r"[ ]+" + MAC_RE_COLON  # type: str

    def test(self):  # type: () -> bool
        return check_command("arp")

    def get(self, arg):  # type: (str) -> Optional[str]
        return _search(re.escape(arg) + self._regex, _popen("arp", "-an"))


class IfconfigOpenbsd(Method):
    platforms = {"openbsd"}
    method_type = "iface"
    _regex = r"lladdr " + MAC_RE_COLON  # type: str

    def test(self):  # type: () -> bool
        return check_command("ifconfig")

    def get(self, arg):  # type: (str) -> Optional[str]
        return _search(self._regex, _popen("ifconfig", arg))


class IfconfigEther(Method):
    platforms = {"darwin", "freebsd"}
    method_type = "iface"
    _tested_arg = False  # type: bool
    _iface_arg = False  # type: bool
    _arg_regex = r".*ether " + MAC_RE_COLON  # type: str
    _blank_regex = r"ether " + MAC_RE_COLON  # type: str

    def test(self):  # type: () -> bool
        return check_command("ifconfig")

    def get(self, arg):  # type: (str) -> Optional[str]
        # Check if this version of "ifconfig" accepts an interface argument
        command_output = ""
        if not self._tested_arg:
            try:
                command_output = _popen("ifconfig", arg)
                self._iface_arg = True
            except CalledProcessError:
                self._iface_arg = False
            self._tested_arg = True

        if self._iface_arg:
            if not command_output:  # Don't repeat work on first run
                command_output = _popen("ifconfig", arg)
            return _search(arg + self._arg_regex, command_output)
        else:
            return _search(self._blank_regex, _popen("ifconfig", ""))


# TODO: sample of ifconfig on WSL (it uses "ether")
class IfconfigLinux(Method):
    platforms = {"linux", "wsl"}
    method_type = "iface"
    # "ether " : modern Ubuntu
    # "HWaddr" : others
    _regexes = [r"ether " + MAC_RE_COLON, r"HWaddr " + MAC_RE_COLON]  # type: List[str]
    _working_regex = ""  # type: str

    def test(self):  # type: () -> bool
        return check_command("ifconfig")

    def get(self, arg):  # type: (str) -> Optional[str]
        try:
            command_output = _popen("ifconfig", arg)
        except CalledProcessError as err:
            # Return code of 1 means interface doesn't exist
            if err.returncode == 1:
                return None
            else:
                raise err
        if self._working_regex:
            # Use regex that worked previously. This can still return None in
            # the case of interface not existing, but at least it's a bit faster.
            return _search(self._working_regex, command_output)
        # See if either regex matches
        for regex in self._regexes:
            result = _search(regex, command_output)
            if result:
                self._working_regex = regex
                return result
        return None


class IfconfigOther(Method):
    """Wild 'Shot in the Dark' attempt at ``ifconfig`` for unknown platforms."""

    platforms = {"linux", "other"}
    method_type = "iface"
    # "-av": Tru64 system?
    _args = (
        ("", (r".*?ether ", r".*?HWaddr ")),
        ("-a", r".*?HWaddr "),
        ("-v", r".*?HWaddr "),
        ("-av", r".*?Ether "),
    )
    _args_tested = False  # type: bool
    _good_pair = []  # type: List[Union[str, Tuple[str, str]]]

    def test(self):  # type: () -> bool
        return check_command("ifconfig")

    def get(self, arg):  # type: (str) -> Optional[str]
        if not arg:
            return None
        # Ensure output from testing command on first call isn't wasted
        command_output = ""
        # Test which arguments are valid to the command
        if not self._args_tested:
            for pair_to_test in self._args:
                try:
                    command_output = _popen("ifconfig", pair_to_test[0])
                    self._good_pair = list(pair_to_test)  # noqa: T484
                    if isinstance(self._good_pair[1], str):
                        self._good_pair[1] += MAC_RE_COLON
                    break
                except CalledProcessError as ex:
                    if DEBUG:
                        log.debug(
                            "IfconfigOther pair test failed for (%s, %s): %s",
                            pair_to_test[0],
                            pair_to_test[1],
                            str(ex),
                        )
            if not self._good_pair:
                self.unusable = True
                return None
            self._args_tested = True
        if not command_output and isinstance(self._good_pair[0], str):
            command_output = _popen("ifconfig", self._good_pair[0])
        # Handle the two possible search terms
        if isinstance(self._good_pair[1], tuple):
            for term in self._good_pair[1]:
                regex = term + MAC_RE_COLON
                result = _search(re.escape(arg) + regex, command_output)
                if result:
                    # changes type from tuple to str, so the else statement
                    # will be hit on the next call to this method
                    self._good_pair[1] = regex
                    return result
            return None
        else:
            return _search(re.escape(arg) + self._good_pair[1], command_output)


# TODO: add these for Android 6.0.1
# (r"state UP.*\n.*ether " + MAC_RE_COLON, 0, "ip", ["link","addr"]),
# (r"wlan.*\n.*ether " + MAC_RE_COLON, 0, "ip", ["link","addr"]),
# (r"ether " + MAC_RE_COLON, 0, "ip", ["link","addr"]),


# TODO: sample of "ip link" on WSL
# TODO: sample of "ip link" on Android (use Vagrant)
# TODO: sample of "ip link eth0" on Ubuntu (use Vagrant)
class IpLinkIface(Method):
    platforms = {"linux", "wsl", "other"}
    method_type = "iface"
    _regex = r".*\n.*link/ether " + MAC_RE_COLON  # type: str
    _tested_arg = False  # type: bool
    _iface_arg = False  # type: bool

    def test(self):  # type: () -> bool
        return check_command("ip")

    def get(self, arg):  # type: (str) -> Optional[str]
        # Check if this version of "ip link" accepts an interface argument
        # Not accepting one is a quirk of older versions of 'iproute2'
        command_output = ""
        if not self._tested_arg:
            try:
                command_output = _popen("ip", "link " + arg)
                self._iface_arg = True
            except CalledProcessError as err:
                # Output: 'Command "eth0" is unknown, try "ip link help"'
                if err.returncode != 255:
                    raise err
            self._tested_arg = True
        if self._iface_arg:
            if not command_output:  # Don't repeat work on first run
                command_output = _popen("ip", "link " + arg)
            return _search(arg + self._regex, command_output)
        else:
            return _search(arg + self._regex, _popen("ip", "link"))


class NetstatIface(Method):
    platforms = {"linux", "wsl", "other"}
    method_type = "iface"

    # ".*?": non-greedy
    # https://docs.python.org/3/howto/regex.html#greedy-versus-non-greedy
    _regexes = [
        r": .*?ether " + MAC_RE_COLON,
        r": .*?HWaddr " + MAC_RE_COLON,
    ]  # type: List[str]
    _working_regex = ""  # type: str

    def test(self):  # type: () -> bool
        return check_command("netstat")

    # TODO: consolidate the parsing logic between IfconfigOther and netstat
    def get(self, arg):  # type: (str) -> Optional[str]
        # NOTE: netstat and ifconfig pull from the same kernel source and
        # therefore have the same output format on the same platform.
        command_output = _popen("netstat", "-iae")
        if self._working_regex:
            # Use regex that worked previously. This can still return None in
            # the case of interface not existing, but at least it's a bit faster.
            return _search(arg + self._working_regex, command_output, flags=re.DOTALL)
        # See if either regex matches
        for regex in self._regexes:
            result = _search(arg + regex, command_output, flags=re.DOTALL)
            if result:
                self._working_regex = regex
                return result
        return None


class IpNeighShow(Method):
    platforms = {"linux", "other"}
    method_type = "ip"

    def test(self):  # type: () -> bool
        return check_command("ip")

    def get(self, arg):  # type: (str) -> Optional[str]
        output = _popen("ip", "neighbor show %s" % arg)
        if output:
            # Note: the space prevents accidental matching of partial IPs
            return (
                output.partition(arg + " ")[2].partition("lladdr")[2].strip().split()[0]
            )
        return None


class ArpVariousArgs(Method):
    platforms = {"linux", "darwin", "other"}
    method_type = "ip"
    _regex_std = r"\)\s+at\s+" + MAC_RE_COLON  # type: str
    _regex_darwin = r"\)\s+at\s+" + MAC_RE_DARWIN  # type: str
    _args = (
        ("", True),  # arp 192.168.1.1
        # Linux
        ("-an", False),  # arp -an
        ("-an", True),  # arp -an 192.168.1.1
        # Darwin, WSL, Linux distros???
        ("-a", False),  # arp -a
        ("-a", True),  # arp -a 192.168.1.1
    )
    _args_tested = False  # type: bool
    _good_pair = ()  # type: Union[Tuple, Tuple[str, bool]]
    _good_regex = ""  # type: str

    def test(self):  # type: () -> bool
        return check_command("arp")

    def get(self, arg):  # type: (str) -> Optional[str]
        if not arg:
            return None
        # Ensure output from testing command on first call isn't wasted
        command_output = ""

        # Test which arguments are valid to the command
        # This will NOT test which regex is valid
        if not self._args_tested:
            for pair_to_test in self._args:
                try:
                    cmd_args = [pair_to_test[0]]
                    # if True, then include IP as a command argument
                    if pair_to_test[1]:
                        cmd_args.append(arg)
                    command_output = _popen("arp", *cmd_args)
                    self._good_pair = pair_to_test
                    break
                except CalledProcessError as ex:
                    if DEBUG:
                        log.debug(
                            "ArpVariousArgs pair test failed for (%s, %s): %s",
                            pair_to_test[0],
                            pair_to_test[1],
                            str(ex),
                        )
            if not self._good_pair:
                self.unusable = True
                return None
            self._args_tested = True
        if not command_output:
            # if True, then include IP as a command argument
            cmd_args = [self._good_pair[0]]
            if self._good_pair[1]:
                cmd_args.append(arg)
            command_output = _popen("arp", *cmd_args)
        escaped = re.escape(arg)
        if self._good_regex:
            return _search(r"\(" + escaped + self._good_regex, command_output)
        # try linux regex first
        # try darwin regex next
        #   if a regex succeeds the first time, cache the successful regex
        #   otherwise, don't bother, since it's a miss anyway
        for regex in (self._regex_std, self._regex_darwin):
            # NOTE: Darwin regex will return MACs without leading zeroes,
            # e.g. "58:6d:8f:7:c9:94" instead of "58:6d:8f:07:c9:94"
            found = _search(r"\(" + escaped + regex, command_output)
            if found:
                self._good_regex = regex
                return found
        return None


class DefaultIfaceLinuxRouteFile(Method):
    """Get the default interface by reading ``/proc/net/route``.

    This is the same source as the ``route`` command, however it's much
    faster to read this file than to call ``route``. If it fails for whatever
    reason, we can fall back on the system commands (e.g for a platform
    that has a route command, but maybe doesn't use ``/proc``?).
    """

    platforms = {"linux", "wsl"}
    method_type = "default_iface"

    def test(self):  # type: () -> bool
        return check_path("/proc/net/route")

    def get(self, arg=""):  # type: (str) -> Optional[str]
        data = _read_file("/proc/net/route")
        if data is not None and len(data) > 1:
            for line in data.split("\n")[1:-1]:
                iface_name, dest = line.split("\t")[:2]
                if dest == "00000000":
                    return iface_name
        return None


# TODO: WSL ip route sample (compare to ubuntu)
# TODO: Android ip route sample
class DefaultIfaceRouteCommand(Method):
    platforms = {"linux", "wsl", "other"}
    method_type = "default_iface"

    def test(self):  # type: () -> bool
        return check_command("route")

    def get(self, arg=""):  # type: (str) -> Optional[str]
        output = _popen("route", "-n")
        try:
            return output.partition("0.0.0.0")[2].partition("\n")[0].split()[-1]
        except IndexError as ex:  # index errors means no default route in output?
            log.debug("DefaultIfaceRouteCommand failed for %s: %s", arg, str(ex))
            return None


# TODO: WSL ip route list sample (compare to ubuntu)
# TODO: Android ip route list sample
class DefaultIfaceIpRoute(Method):
    platforms = {"linux", "wsl", "other"}
    method_type = "default_iface"

    def test(self):  # type: () -> bool
        return check_command("ip")

    def get(self, arg=""):  # type: (str) -> Optional[str]
        output = _popen("ip", "route list 0/0")
        try:
            return output.partition("dev")[2].partition("proto")[0].strip()
        except IndexError as ex:
            log.debug("DefaultIfaceIpRoute failed for %s: %s", arg, str(ex))
            return None


class DefaultIfaceOpenBsd(Method):
    platforms = {"openbsd"}
    method_type = "default_iface"

    def test(self):  # type: () -> bool
        return check_command("route")

    def get(self, arg=""):  # type: (str) -> Optional[str]
        output = _popen("route", "-nq show -inet -gateway -priority 1")
        try:
            return output.partition("127.0.0.1")[0].strip().rpartition(" ")[2]
        except IndexError as ex:
            log.debug("DefaultIfaceOpenBsd failed for %s: %s", arg, str(ex))
            return None


class DefaultIfaceFreeBsd(Method):
    platforms = {"freebsd"}
    method_type = "default_iface"

    def test(self):  # type: () -> bool
        return check_command("netstat")

    def get(self, arg=""):  # type: (str) -> Optional[str]
        output = _popen("netstat", "-r")
        return _search(r"default[ ]+\S+[ ]+\S+[ ]+(\S+)[\r\n]+", output)


# TODO: order methods by effectiveness/reliability
#   Use a class attribute maybe? e.g. "score", then sort by score in cache
METHODS = [
    ArpFile,
    SysIfaceFile,
    CtypesHost,
    FcntlIface,
    UuidArpGetNode,
    UuidLanscan,
    GetmacExe,
    IpconfigExe,
    WmicExe,
    ArpExe,
    DarwinNetworksetup,
    ArpFreebsd,
    ArpOpenbsd,
    IfconfigOpenbsd,
    IfconfigEther,
    IfconfigLinux,
    IfconfigOther,
    IpLinkIface,
    NetstatIface,
    IpNeighShow,
    ArpVariousArgs,
    DefaultIfaceLinuxRouteFile,
    DefaultIfaceRouteCommand,
    DefaultIfaceOpenBsd,
    DefaultIfaceFreeBsd,
]


# Primary method to use for a given method type
METHOD_CACHE = {
    "ip4": None,
    "ip6": None,
    "iface": None,
    "default_iface": None,
}  # type: Dict[str, Optional[Method]]


# Order of methods is determined by:
#   Platform + version
#   Performance (file read > command)
#   Reliability (how well I know/understand the command to work)
FALLBACK_CACHE = {
    "ip4": [],
    "ip6": [],
    "iface": [],
    "default_iface": [],
}  # type: Dict[str, List[Method]]


DEFAULT_IFACE = ""  # type: str


def initialize_method_cache(method_type):  # type: (str) -> bool
    """Find methods that work.

    Args:
        method_type: method type to initialize the cache for.
            Allowed values are: ip | ip4 | ip6 | iface | default_iface
    """
    log.debug("Initializing '%s' method cache (platform: '%s')", method_type, PLATFORM)
    if METHOD_CACHE.get(method_type) or (
        method_type == "ip" and (METHOD_CACHE.get("ip4") and METHOD_CACHE.get("ip6"))
    ):
        if DEBUG:
            log.debug("Cache already initialized for '%s'", method_type)
        return True

    # Filter methods by the platform we're running on
    platform_methods = [
        m for m in METHODS if PLATFORM in m.platforms
    ]  # type: List[Type[Method]]
    if not platform_methods:
        # If there isn't a method for the current platform,
        # then fallback to the generic platform "other".
        log.warning(
            "No methods for platform '%s'! Your system may not be supported. "
            "Falling back to platform 'other'",
            PLATFORM,
        )
        platform_methods = [m for m in METHODS if "other" in m.platforms]
    if DEBUG:
        meth_strs = ", ".join(str(pm) for pm in platform_methods)  # type: str
        log.debug("'%s' platform_methods: %s", method_type, meth_strs)

    # Filter methods by the type of MAC we're looking for, such as "ip"
    # for remote host methods or "iface" for local interface methods.
    type_methods = [
        pm
        for pm in platform_methods
        if pm.method_type == method_type
        or (pm.method_type == "ip" and method_type in ["ip4", "ip6"])
    ]  # type: List[Type[Method]]
    if not type_methods:
        log.critical("No valid methods found for MAC type '%s'", method_type)
        return False
    if DEBUG:
        type_strs = ", ".join(str(tm) for tm in type_methods)  # type: str
        log.debug("'%s' type_methods: %s", method_type, type_strs)

    # Determine which methods work on the current system
    tested_methods = []  # type: List[Method]
    for method_class in type_methods:
        method_instance = method_class()  # type: Method
        try:
            test_result = method_instance.test()  # type: bool
        except Exception:
            test_result = False
        if test_result:
            tested_methods.append(method_instance)
            # First successful test goes in the cache
            if method_type == "ip":
                if not METHOD_CACHE["ip4"]:
                    METHOD_CACHE["ip4"] = method_instance
                if not METHOD_CACHE["ip6"]:
                    METHOD_CACHE["ip6"] = method_instance
            else:
                if not METHOD_CACHE[method_type]:
                    METHOD_CACHE[method_type] = method_instance
        else:
            if DEBUG:
                log.debug("Test failed for method '%s'", str(method_instance))
    if not tested_methods:
        log.critical(
            "All %d '%s' methods failed to test!", len(type_methods), method_type
        )
        return False

    # Populate fallback cache with all the tested methods, minus the currently active method
    if METHOD_CACHE.get(method_type):
        tested_methods.remove(METHOD_CACHE[method_type])  # noqa: T484
    FALLBACK_CACHE[method_type] = tested_methods

    if DEBUG:
        tested_strs = ", ".join(str(ts) for ts in tested_methods)  # type: str
        log.debug("'%s' tested_methods: %s", method_type, tested_strs)
        log.debug(
            "Current method cache: %s",
            str({k: str(v) for k, v in METHOD_CACHE.items()}),
        )
    log.debug("Finished initializing '%s' method cache", method_type)
    return True


def get_by_method(method_type, arg=""):  # type: (str, str) -> Optional[str]
    """Query for a MAC using a specific method.

    Args:
        method_type: method type to initialize the cache for.
            Allowed values are: ip4 | ip6 | iface | default_iface
        arg: Argument to pass to the method, e.g. a interface name or IP address
    """
    # TODO(rewrite): net_ok argument, check network_request on method in CACHE,
    #  if not then keep checking for method in FALLBACK_CACHE that has network_request

    #  TODO(rewrite): function to query methods out of cache,
    #   if they throw exception, pick one out of fallback.
    #   the current method in cache should NOT be in fallback cache

    if not arg and method_type != "default_iface":
        log.error("Empty arg for method '%s' (raw value: %s)", method_type, repr(arg))
        return None

    method = METHOD_CACHE.get(method_type)  # type: Optional[Method]
    # Initialize the cache if it hasn't been already
    if not method:
        initialize_method_cache(method_type)
        method = METHOD_CACHE[method_type]
    if not method:
        log.error(
            "Initialization failed for method %s. It may not be supported "
            "on this platform or another issue occurred.",
            method_type,
        )
        return None

    try:
        result = method.get(arg)
    except Exception as ex:
        log.warning(
            "Cached Method '%s' failed for '%s' lookup: %s",
            str(method),
            method_type,
            str(ex),
        )
        result = None
        # TODO(rewrite):
        #  When exception occurs, remove from cache
        #  and reinitialize with next candidate
        #  For example, if get() call to getmac.exe
        #  returns 1 then it's not valid
        # TODO(rewrite): handle method throwing exception, use to mark as non-usable
        #   Do NOT mark return code 1 on a process as non-usable though!
        #   Example of return code 1 on ifconfig from WSL:
        #     Blake:goesc$ ifconfig eth8
        #     eth8: error fetching interface information: Device not found
        #     Blake:goesc$ echo $?
        #     1

        # TODO(rewrite): use the "Unusable" method attribute

    # Log normal get() failures if debugging is enabled
    if DEBUG and not result:
        log.debug("Method '%s' failed for '%s' lookup", str(method), method_type)
    return result


def get_mac_address(
    interface=None, ip=None, ip6=None, hostname=None, network_request=True
):
    # type: (Optional[str], Optional[str], Optional[str], Optional[str], bool) -> Optional[str]
    """Get a Unicast IEEE 802 MAC-48 address from a local interface or remote host.

    You must only use ONE of the first four arguments (interface, ip, ip6, hostname).
    If none of the arguments are selected, the default network interface for
    the system will be used.

    Exceptions are handled silently and returned as a `None`.

    .. warning::
       You MUST provide str-typed arguments, REGARDLESS of Python version.

    .. note::
       ``localhost`` or ``127.0.0.1`` will always return ``"00:00:00:00:00:00"``

    .. note::
       It is assumed that you are using Ethernet or Wi-Fi. While other protocols
       such as Bluetooth may work, this has not been tested and should not be
       relied upon. If you need this functionality, please open an issue!
       (or better yet, a Pull Request ;)

    Args:
        interface (str): Name of a local network interface (e.g "Ethernet 3", "eth0", "ens32")
        ip (str): Canonical dotted decimal IPv4 address of a remote host (e.g 192.168.0.1)
        ip6 (str): Canonical shortened IPv6 address of a remote host (e.g ff02::1:ffe7:7f19)
        hostname (str): DNS hostname of a remote host (e.g "router1.mycorp.com", "localhost")
        network_request (bool): Send a UDP packet to a remote host to populate
            the ARP/NDP tables for IPv4/IPv6. The port this packet is sent to can
            be configured using the module variable `getmac.PORT`.
    Returns:
        Lowercase colon-separated MAC address, or None if one could not be
        found or there was an error.
    """
    # TODO: method string
    # TODO: CLI argument for method string
    # TODO: method class
    # TODO: method instance

    # TODO: force platform name (e.g. linux). define a set of platform strings.
    # TODO: CLI argument to force platform name

    if PY2 or (sys.version_info[0] == 3 and sys.version_info[1] < 6):
        global WARNED_UNSUPPORTED_PYTHONS
        if not WARNED_UNSUPPORTED_PYTHONS:
            warning_string = (
                "Support for Python versions < 3.6 is deprecated and will be "
                "removed in getmac 1.0.0. If you are stuck on an unsupported "
                "Python, considor loosely pinning the version of this package "
                'in your dependency list, e.g. "getmac<1".'
            )
            warnings.warn(warning_string, DeprecationWarning)
            log.warning(warning_string)  # Ensure it appears in any logs
            WARNED_UNSUPPORTED_PYTHONS = True

    if (hostname and hostname == "localhost") or (ip and ip == "127.0.0.1"):
        return "00:00:00:00:00:00"

    # Resolve hostname to an IP address
    if hostname:
        ip = socket.gethostbyname(hostname)

    # Populate the ARP table by sending a empty UDP packet to a high port
    if network_request and (ip or ip6):
        if ip:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            if ip:
                s.sendto(b"", (ip, PORT))
            else:
                s.sendto(b"", (ip6, PORT))
        except Exception:
            log.error("Failed to send ARP table population packet")
            if DEBUG:
                log.debug(traceback.format_exc())
        finally:
            s.close()

    # Setup the address hunt based on the arguments specified
    # mac = None
    if ip6:
        if not socket.has_ipv6:
            log.error(
                "Cannot get the MAC address of a IPv6 host: "
                "IPv6 is not supported on this system"
            )
            return None
        elif ":" not in ip6:
            log.error("Invalid IPv6 address: %s", ip6)
            return None
        mac = get_by_method("ip6", ip6)
    elif ip:
        mac = get_by_method("ip4", ip)
    elif interface:
        mac = get_by_method("iface", interface)
    else:  # Default to searching for interface
        # Default to finding MAC of the interface with the default route
        if WINDOWS and network_request:
            default_iface_ip = _fetch_ip_using_dns()
            mac = get_by_method("ip4", default_iface_ip)
        elif WINDOWS:
            # TODO: implement proper default interface detection on windows
            #   (add a Method subclass to implement DefaultIface on Windows)
            mac = get_by_method("iface", "Ethernet")
        else:
            global DEFAULT_IFACE
            if not DEFAULT_IFACE:
                DEFAULT_IFACE = get_by_method("default_iface")  # noqa: T484
                if DEFAULT_IFACE:
                    DEFAULT_IFACE = str(DEFAULT_IFACE).strip()
                # TODO: better fallback if default iface lookup fails
                if not DEFAULT_IFACE and BSD:
                    DEFAULT_IFACE = "em0"
                elif not DEFAULT_IFACE:  # OSX, maybe?
                    DEFAULT_IFACE = "en0"
            mac = get_by_method("iface", DEFAULT_IFACE)
    log.debug("Raw MAC found: %s", mac)
    return _clean_mac(mac)
