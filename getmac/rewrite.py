import ctypes
import logging
import os
import platform
import re
import shutil
import socket
import struct
import sys
from subprocess import CalledProcessError

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
        from typing import Dict, Optional, Set
except ImportError:
    pass


from .getmac import _read_file, _search, _uuid_convert, _popen


PLATFORM = _SYST.lower()
if PLATFORM == "linux" and "Microsoft" in platform.version():
    PLATFORM = "wsl"

CMD_STATUS_CACHE = {}  # type: Dict[str, bool]


# TODO: find alternative to shutil.which() on Python 2
#   https://github.com/mbr/shutilwhich/blob/master/shutilwhich/lib.py
def check_command(command):  # type: (str) -> bool
    if command not in CMD_STATUS_CACHE:
        CMD_STATUS_CACHE[command] = bool(shutil.which(command, path=PATH))
    return CMD_STATUS_CACHE[command]


def check_file(filepath):  # type: (str) -> bool
    return os.path.exists(filepath) and os.access(filepath, os.R_OK)


# TODO: API to add/remove methods at runtime (including new, custom methods)
# TODO: document quirks/notes about each method in class docstring
# TODO: cache imports done during test for use during get(), reuse
#   Use __import__() or importlib?
# TODO: parameterize regexes? (any faster?)
class Method:
    # VALUES: {linux, windows, bsd, darwin, freebsd, openbsd, wsl, other}
    # TODO: platform versions/releases, e.g. Windows 7 vs 10, Ubuntu 12 vs 20
    platforms = set()  # type: Set[str]
    # VALUES: {ip, ip4, ip6, iface, default_iface}
    method_type = ""  # type: str
    # If the method makes a network request as part of the check
    net_request = False  # type: bool
    # (TODO) If current system supports. Dynamically set at runtime?
    #   This would let each method do more fine-grained version checking
    supported = False  # type: bool

    def test(self):  # type: () -> bool
        pass

    def get(self, arg):  # type: (str) -> Optional[str]
        pass


class ArpFile(Method):
    platforms = {"linux"}
    method_type = "ip"
    _path = "/proc/net/arp"

    def test(self):  # type: () -> bool
        return check_file(self._path)

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
    _path = "/sys/class/net/"

    def test(self):  # type: () -> bool
        # TODO: imperfect, but should work well enough
        return check_file(self._path)

    def get(self, arg):  # type: (str) -> Optional[str]
        data = _read_file(self._path + arg + "/address")
        # Sometimes this can be empty or a single newline character
        return None if data is not None and len(data) < 17 else data


class UuidLanscan(Method):
    platforms = {"other"}  # TODO: "other" platform?
    method_type = "iface"

    def test(self):  # type: () -> bool
        try:
            from uuid import _find_mac
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


# TODO: do we want to keep this around? It calls 3 command and is
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
    platforms = {"windows"}
    method_type = "iface"
    _regexes = [
        # Connection Name
        (r"\r\n", r".*" + MAC_RE_DASH + r".*\r\n"),
        # Network Adapter (the human-readable name)
        (r"\r\n.*", r".*" + MAC_RE_DASH + r".*\r\n")
    ]
    _champ = ()

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


class IpconfigExe(Method):
    platforms = {"windows"}
    method_type = "iface"
    _regex = r"(?:\n?[^\n]*){1,8}Physical Address[ .:]+" + MAC_RE_DASH + r"\r\n"

    def test(self):  # type: () -> bool
        return check_command("ipconfig.exe")

    def get(self, arg):  # type: (str) -> Optional[str]
        return _search(arg + self._regex, _popen("ipconfig.exe", "/all"))


class WimcExe(Method):
    platforms = {"windows"}
    method_type = "iface"

    def test(self):  # type: () -> bool
        return check_command("wmic.exe")

    def get(self, arg):  # type: (str) -> Optional[str]
        command_output = _popen(
            "wmic.exe",
            "nic where \"NetConnectionID = '%s'\" get " "MACAddress /value" % arg,
        )
        # TODO: check if returned anything before exception on index failure
        return command_output.strip().partition("=")[2]


class ArpExe(Method):
    platforms = {"windows", "wsl"}
    method_type = "ip"

    def test(self):  # type: () -> bool
        return check_command("arp.exe")

    def get(self, arg):  # type: (str) -> Optional[str]
        return _search(MAC_RE_DASH, _popen("arp.exe", "-a %s" % arg))


class DarwinNetworksetup(Method):
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
    _regex = r"[ ]+" + MAC_RE_COLON

    def test(self):  # type: () -> bool
        return check_command("arp")

    def get(self, arg):  # type: (str) -> Optional[str]
        return _search(re.escape(arg) + self._regex, _popen("arp", "-an"))


class IfconfigOpenbsd(Method):
    platforms = {"openbsd"}
    method_type = "iface"
    _regex = r"lladdr " + MAC_RE_COLON

    def test(self):  # type: () -> bool
        return check_command("ifconfig")

    def get(self, arg):  # type: (str) -> Optional[str]
        return _search(self._regex, _popen("ifconfig", arg))


class IfconfigEther(Method):
    platforms = {"darwin", "freebsd"}
    method_type = "iface"

    def test(self):  # type: () -> bool
        return check_command("ifconfig")

    def get(self, arg):  # type: (str) -> Optional[str]
        # TODO: check which works, with interface arg or without
        #   Former is also used on Ubuntu...
        # (r"ether " + MAC_RE_COLON, 0, "ifconfig", [to_find]),
        # # Alternative match for ifconfig if it fails
        # (to_find + r".*ether " + MAC_RE_COLON, 0, "ifconfig", [""]),
        pass


# TODO: sample of ifconfig on WSL (it uses "ether")
class IfconfigLinux(Method):
    platforms = {"linux", "wsl"}
    method_type = "iface"
    # "ether " : modern Ubuntu
    # "HWaddr" : others
    _regexes = [r"ether " + MAC_RE_COLON, r"HWaddr " + MAC_RE_COLON]
    _champ = ""  # winner winner chicken dinner

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
        if self._champ:
            # Use regex that worked previously. This can still return None in
            # the case of interface not existing, but at least it's a bit faster.
            return _search(self._champ, command_output)
        for regex in self._regexes:  # See if either regex matches
            result = _search(regex, command_output)
            if result:
                self._champ = regex  # We have our Apex champion
                return result


class IfconfigOther(Method):
    """Wild 'Shot in the Dark' attempt at ifconfig for unknown platforms."""
    platforms = {"other"}
    method_type = "iface"

    def test(self):  # type: () -> bool
        return check_command("ifconfig")

    def get(self, arg):  # type: (str) -> Optional[str]
        # TODO: implement
        # ifconfig
        #   ether
        #   HWaddr

        # ifconfig -a
        #   HWaddr

        # ifconfig -v
        #   HWaddr

        # ifconfig -av (Tru64?)
        #   Ether
        pass


# TODO: sample of "ip link" on WSL
# TODO: sample of "ip link" on Android
# TODO: sample of "ip link eth0" on Ubuntu
class IpLinkIface(Method):
    platforms = {"linux", "wsl", "other"}
    method_type = "iface"
    _regex = r".*\n.*link/ether " + MAC_RE_COLON
    _tested_arg = False
    _iface_arg = False

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
    _regex = r".*HWaddr " + MAC_RE_COLON

    def test(self):  # type: () -> bool
        return check_command("netstat")

    def get(self, arg):  # type: (str) -> Optional[str]
        return _search(arg + self._regex, _popen("netstat", "-iae"))


class IpNeighShow(Method):
    platforms = {"linux", "other"}
    method_type = "ip"

    def test(self):  # type: () -> bool
        return check_command("ip")

    def get(self, arg):  # type: (str) -> Optional[str]
        output = _popen("ip", "neighbor show %s" % arg)
        # TODO: check if returned anything before exception on index failure
        return output.partition(arg)[2].partition("lladdr")[2].strip().split()[0]


class ArpVariousArgs(Method):
    platforms = {"linux", "darwin", "other"}
    method_type = "ip"
    _regex_std = r"\)\s+at\s+" + MAC_RE_COLON
    _regex_darwin = r"\)\s+at\s+" + MAC_RE_DARWIN

    def test(self):  # type: () -> bool
        return check_command("arp")

    def get(self, arg):  # type: (str) -> Optional[str]
        # TODO: linux => also try "-an", "-an %s" % arg
        # TODO: darwin => also try "-a", "-a %s" % arg
        # TODO: finish implementing
        command_output = _popen("arp", arg)
        found = _search(r"\(" + re.escape(arg) + self._regex_std, command_output)
        found = _search(r"\(" + re.escape(arg) + self._regex_darwin, command_output)


class DefaultIfaceLinuxRouteFile(Method):
    """Get the default interface by reading /proc/net/route.

    This is the same source as the `route` command, however it's much
    faster to read this file than to call `route`. If it fails for whatever
    reason, we can fall back on the system commands (e.g for a platform
    that has a route command, but maybe doesn't use /proc?).
    """
    platforms = {"linux", "wsl"}
    method_type = "default_iface"

    def test(self):  # type: () -> bool
        return check_file("/proc/net/route")

    def get(self, arg):  # type: (str) -> Optional[str]
        data = _read_file("/proc/net/route")
        if data is not None and len(data) > 1:
            for line in data.split("\n")[1:-1]:
                iface_name, dest = line.split("\t")[:2]
                if dest == "00000000":
                    return iface_name


class DefaultIfaceRouteCommand(Method):
    platforms = {"linux", "wsl", "other"}
    method_type = "default_iface"

    def test(self):  # type: () -> bool
        return check_command("route")

    def get(self, arg):  # type: (str) -> Optional[str]
        output = _popen("route", "-n")
        # TODO: handle index errors
        return output.partition("0.0.0.0")[2].partition("\n")[0].split()[-1]


class DefaultIfaceIpRoute(Method):
    platforms = {"linux", "wsl", "other"}
    method_type = "default_iface"

    def test(self):  # type: () -> bool
        return check_command("ip")

    def get(self, arg):  # type: (str) -> Optional[str]
        output = _popen("ip", "route list 0/0")
        # TODO: handle index errors
        return output.partition("dev")[2].partition("proto")[0].strip()


class DefaultIfaceOpenBsd(Method):
    platforms = {"openbsd"}
    method_type = "default_iface"

    def test(self):  # type: () -> bool
        return check_command("route")

    def get(self, arg):  # type: (str) -> Optional[str]
        output = _popen("route", "-nq show -inet -gateway -priority 1")
        # TODO: handle index errors
        return output.partition("127.0.0.1")[0].strip().rpartition(" ")[2]


class DefaultIfaceFreeBsd(Method):
    platforms = {"freebsd"}
    method_type = "default_iface"

    def test(self):  # type: () -> bool
        return check_command("netstat")

    def get(self, arg):  # type: (str) -> Optional[str]
        output = _popen("netstat", "-r")
        return _search(r"default[ ]+\S+[ ]+\S+[ ]+(\S+)\n", output)


# TODO: ordering of methods by effectiveness/reliability
METHODS = [
    ArpFile, SysIfaceFile, CtypesHost, FcntlIface, UuidArpGetNode, UuidLanscan,
    GetmacExe, IpconfigExe, WimcExe, ArpExe, DarwinNetworksetup, ArpFreebsd,
    ArpOpenbsd, IfconfigOpenbsd, IfconfigEther, IfconfigLinux, IfconfigOther,
    IpLinkIface, NetstatIface, IpNeighShow, ArpVariousArgs,
    DefaultIfaceLinuxRouteFile, DefaultIfaceRouteCommand, DefaultIfaceOpenBsd,
    DefaultIfaceFreeBsd,
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

    # TODO: log platform checking/filtering when DEBUG is enabled
    type_methods = [m for m in platform_methods
                    if m.method_type == mac_type
                    or (m.method_type == "ip" and mac_type in ["ip4", "ip6"])]
    if not type_methods:
        print("No valid methods for type ", mac_type)

    # TODO: log test() failures when DEBUG is enabled
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

    # TODO: handle method throwing exception, use to mark as non-usable
    #   Do NOT mark return code 1 on a process as non-usable though!

    # Example from WSL:
    """
    Blake:goesc$ ifconfig eth8
    eth8: error fetching interface information: Device not found
    Blake:goesc$ echo $?
    1
    """

    # TODO: log get() failures
    # TODO: exception handling when calling get(), log all exceptions
    #   When exception occurs, remove from cache and reinitialize with next candidate
    #   For example, if get() call to getmac.exe returns 1 then it's not valid
