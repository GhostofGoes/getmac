import ctypes
import logging
import os
import platform
import re
import shlex
import shutil
import socket
import struct
import sys
import traceback
from subprocess import check_output

try:  # Python 3
    from subprocess import DEVNULL  # type: ignore
except ImportError:  # Python 2
    DEVNULL = open(os.devnull, "wb")  # type: ignore

# Configure logging
log = logging.getLogger("getmac")
log.addHandler(logging.NullHandler())

__version__ = "0.8.1"
PY2 = sys.version_info[0] == 2

# Configurable settings
DEBUG = 0
PORT = 55555

# Platform identifiers
_SYST = platform.system()
if _SYST == "Java":
    try:
        import java.lang

        _SYST = str(java.lang.System.getProperty("os.name"))
    except ImportError:
        log.critical("Can't determine OS: couldn't import java.lang on Jython")
WINDOWS = _SYST == "Windows"
DARWIN = _SYST == "Darwin"
OPENBSD = _SYST == "OpenBSD"
FREEBSD = _SYST == "FreeBSD"
BSD = OPENBSD or FREEBSD  # Not including Darwin for now
WSL = False  # Windows Subsystem for Linux (WSL)
LINUX = False
if _SYST == "Linux":
    if "Microsoft" in platform.version():
        WSL = True
    else:
        LINUX = True

PATH = os.environ.get("PATH", os.defpath).split(os.pathsep)
if not WINDOWS:
    PATH.extend(("/sbin", "/usr/sbin"))

# Use a copy of the environment so we don't
# modify the process's current environment.
ENV = dict(os.environ)
ENV["LC_ALL"] = "C"  # Ensure ASCII output so we parse correctly

# Constants
IP4 = 0
IP6 = 1
INTERFACE = 2
HOSTNAME = 3

MAC_RE_COLON = r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"
MAC_RE_DASH = r"([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})"
MAC_RE_DARWIN = r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})"

# Used for mypy (a data type analysis tool)
# If you're copying the code, this section can be safely removed
try:
    from typing import TYPE_CHECKING

    if TYPE_CHECKING:
        from typing import Dict, Optional
except ImportError:
    pass


from .getmac import _read_file, _search, _uuid_convert, _popen


PLATFORM = _SYST.lower()
if PLATFORM == "linux" and "Microsoft" in platform.version():
    PLATFORM = "wsl"


def exists(command):
    # type: (str) -> bool
    return bool(shutil.which(command, path=PATH))


# TODO: API to add custom methods at runtime (also to remove methods)
# TODO: log test() failures when DEBUG is enabled
# TODO: log get() failures
# TODO: exception handling when calling get(), log all exceptions
#   When exception occurs, remove from cache and reinitialize with next candidate
#   For example, if get() call to getmac.exe returns 1 then it's not valid
# TODO: document quirks/notes about each method in class docstring
# TODO: use self/instance to track state between calls e.g. caching
# TODO: cache imports done during test for use during get(), reuse
#   Use __import__() or importlib?
# TODO: parameterize regexes? (any faster?)
class Method:
    # linux windows bsd darwin freebsd openbsd
    # TODO: how to handle wsl
    # TODO: "other" platform (e.g. for lanscan, etc.)
    # TODO: platform versions/releases, e.g. Windows 7 vs 10, Ubuntu 12 vs 20
    platforms = []
    method_type = ""  # ip, ip4, ip6, iface, default_iface
    net_request = False
    # TODO: __slots__?

    def test(self):  # type: () -> bool
        pass

    def get(self, arg):  # type: (str) -> Optional[str]
        pass


class ArpFile(Method):
    platforms = ["linux"]
    method_type = "ip"
    _path = "/proc/net/arp"

    def test(self):  # type: () -> bool
        return os.path.exists(self._path) and os.access(self._path, os.R_OK)

    def get(self, arg):  # type: (str) -> Optional[str]
        data = _read_file(self._path)
        if data is not None and len(data) > 1:
            # Need a space, otherwise a search for 192.168.16.2
            # will match 192.168.16.254 if it comes first!
            return _search(re.escape(arg) + r" .+" + MAC_RE_COLON, data)
        return None


class SysIfaceFile(Method):
    platforms = ["linux"]
    method_type = "iface"
    _path = "/sys/class/net/"

    def test(self):  # type: () -> bool
        # TODO: imperfect, but should work well enough
        return os.path.exists(self._path) and os.access(self._path, os.R_OK)

    def get(self, arg):  # type: (str) -> Optional[str]
        data = _read_file(self._path + arg + "/address")
        # Sometimes this can be empty or a single newline character
        return None if data is not None and len(data) < 17 else data


class UuidLanscan(Method):
    platforms = ["other"]  # TODO: "other" platform?
    method_type = "iface"

    def test(self):  # type: () -> bool
        try:
            from uuid import _find_mac
            return exists("lanscan")
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
    platforms = ["windows"]
    method_type = "ip4"  # TODO: can this be made to work with IPv6?
    net_request = True

    def test(self):  # type: () -> bool
        try:
            return ctypes.windll.wsock32.inet_addr(b'127.0.0.1') > 0
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
            #   We should be explict about only accepting ipv4/ipv6 addresses
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


class FcntlIface(Method):
    platforms = ["linux"]
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


# TODO: do we want to keep this around? It calls 3 command and is
#   quite inefficient. We should just take the methods and use directly.
class UuidArpGetNode(Method):
    platforms = ["linux", "darwin"]
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
            socket.gethostbyname = lambda x: arg
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
    platforms = ["windows"]
    method_type = "iface"

    def test(self):  # type: () -> bool
        return exists("getmac.exe")

    def get(self, arg):  # type: (str) -> Optional[str]
        command_output = _popen("getmac.exe", "/NH /V")

        # Connection Name
        conn_regex = r"\r\n" + arg + r".*" + MAC_RE_DASH + r".*\r\n"

        # Network Adapter (the human-readable name)
        net_regex = r"\r\n.*" + arg + r".*" + MAC_RE_DASH + r".*\r\n"

        for regex in [conn_regex, net_regex]:
            found = _search(regex, command_output)
            if found:
                return found
        return None


class IpconfigExe(Method):
    platforms = ["windows"]
    method_type = "iface"
    _regex = r"(?:\n?[^\n]*){1,8}Physical Address[ .:]+" + MAC_RE_DASH + r"\r\n"

    def test(self):  # type: () -> bool
        return exists("ipconfig.exe")

    def get(self, arg):  # type: (str) -> Optional[str]
        return _search(arg + self._regex, _popen("ipconfig.exe", "/all"))


class WimcExe(Method):
    platforms = ["windows"]
    method_type = "iface"

    def test(self):  # type: () -> bool
        return exists("wmic.exe")

    def get(self, arg):  # type: (str) -> Optional[str]
        command_output = _popen(
            "wmic.exe",
            "nic where \"NetConnectionID = '%s'\" get " "MACAddress /value" % arg,
        )
        # TODO: check if returned anything before exception on index failure
        return command_output.strip().partition("=")[2]


class ArpExe(Method):
    platforms = ["windows", "wsl"]
    method_type = "ip"

    def test(self):  # type: () -> bool
        return exists("arp.exe")

    def get(self, arg):  # type: (str) -> Optional[str]
        return _search(MAC_RE_DASH, _popen("arp.exe", "-a %s" % arg))


class IfconfigEther(Method):
    platforms = ["darwin", "freebsd"]
    method_type = "iface"

    def test(self):  # type: () -> bool
        return exists("ifconfig")

    def get(self, arg):  # type: (str) -> Optional[str]
        # TODO: check which works, with interface arg or without
        # (r"ether " + MAC_RE_COLON, 0, "ifconfig", [to_find]),
        # # Alternative match for ifconfig if it fails
        # (to_find + r".*ether " + MAC_RE_COLON, 0, "ifconfig", [""]),
        pass


class DarwinNetworksetup(Method):
    platforms = ["darwin"]
    method_type = "iface"

    def test(self):  # type: () -> bool
        return exists("networksetup")

    def get(self, arg):  # type: (str) -> Optional[str]
        command_output = _popen("networksetup", "-getmacaddress %s" % arg)
        return _search(MAC_RE_COLON, command_output)


class ArpFreebsd(Method):
    platforms = ["freebsd"]
    method_type = "ip"

    def test(self):  # type: () -> bool
        return exists("arp")

    def get(self, arg):  # type: (str) -> Optional[str]
        regex = r"\(" + re.escape(arg) + r"\)\s+at\s+" + MAC_RE_COLON
        return _search(regex, _popen("arp", arg))


class IfconfigOpenbsd(Method):
    platforms = ["openbsd"]
    method_type = "iface"

    def test(self):  # type: () -> bool
        return exists("ifconfig")

    def get(self, arg):  # type: (str) -> Optional[str]
        return _search(r"lladdr " + MAC_RE_COLON, _popen("ifconfig", arg))


class ArpOpenbsd(Method):
    platforms = ["openbsd"]
    method_type = "ip"
    _regex = r"[ ]+" + MAC_RE_COLON

    def test(self):  # type: () -> bool
        return exists("arp")

    def get(self, arg):  # type: (str) -> Optional[str]
        return _search(re.escape(arg) + self._regex, _popen("arp", "-an"))


# TODO: ordering of methods by effectiveness/reliability
METHODS = [
    ArpFile,
    SysIfaceFile,
    CtypesHost,
    FcntlIface,
    UuidArpGetNode,
    UuidLanscan,
    GetmacExe,
    IpconfigExe,
    WimcExe,
    ArpExe,
    IfconfigEther,
    DarwinNetworksetup,
    ArpFreebsd,
    IfconfigOpenbsd,
    ArpOpenbsd,
]


CACHE = {  # type: Dict[str, Optional[Method]]
    "ip4": None,
    "ip6": None,
    "iface": None,
    "default_iface": None,
}


# Find methods that work
def initialize_method_cache(mac_type):
    """
    mac_type: ip | ip4 | ip6 | iface | default_iface

    # Filter methods by platform
    methods = filter(methods)

    # Filter methods by feasibility


    for method in methods:
        method.test()
    """
    platform_methods = [x for x in METHODS if PLATFORM in x.platforms]
    if not platform_methods:
        print("No valid methods for platform ", PLATFORM)

    type_methods = [m for m in platform_methods
                    if m.method_type == mac_type
                    or (m.method_type == "ip" and mac_type in ["ip4", "ip6"])]
    if not type_methods:
        print("No valid methods for type ", mac_type)

    tested = []
    for method in type_methods:
        if method.test():
            tested.append(method)
            if not CACHE[mac_type]:
                CACHE[mac_type] = method
        else:
            print("Failed to test method ", method.__name__)
    if not tested:
        # CRITICAL FAIL
        print("All methods failed to test")








