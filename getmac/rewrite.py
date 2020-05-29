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
from subprocess import CalledProcessError, check_output

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
else:
    # TODO: Prevent edge case on Windows where our script "getmac.exe"
    #   gets added to the path ahead of the actual Windows getmac.exe
    #   This just handles case where it's in a virtualenv, won't work /w global scripts
    # TODO: remove all Python "scripts" from path? Document this!
    PATH = [p for p in PATH if "\\getmac\\Scripts" not in p]
PATH_STR = os.pathsep.join(PATH)

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
        from typing import Dict, List, Optional, Set
except ImportError:
    pass

PLATFORM = _SYST.lower()
if PLATFORM == "linux" and "Microsoft" in platform.version():
    PLATFORM = "wsl"

CHECK_COMMAND_CACHE = {}  # type: Dict[str, bool]


# TODO (python3): use shutil.which() instead?
# TODO: find alternative to shutil.which() on Python 2
#   https://github.com/mbr/shutilwhich/blob/master/shutilwhich/lib.py
def check_command(command):  # type: (str) -> bool
    if command not in CHECK_COMMAND_CACHE:
        CHECK_COMMAND_CACHE[command] = bool(shutil.which(command, path=PATH_STR))
    return CHECK_COMMAND_CACHE[command]


def check_path(filepath):  # type: (str) -> bool
    return os.path.exists(filepath) and os.access(filepath, os.R_OK)


# TODO: move these functions to a separate "utils" file?
def _read_file(filepath):
    # type: (str) -> Optional[str]
    try:
        with open(filepath) as f:
            return f.read()
    except (OSError, IOError):  # This is IOError on Python 2.7
        log.debug("Could not find file: '%s'", filepath)
        return None


def _search(regex, text, group_index=0):
    # type: (str, str, int) -> Optional[str]
    match = re.search(regex, text)
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


# TODO(python3): Enums for platforms + method types
# TODO: API to add/remove methods at runtime (including new, custom methods)
# TODO: document quirks/notes about each method in class docstring
# TODO: cache imports done during test for use during get(), reuse
#   Use __import__() or importlib?
# TODO: parameterize regexes? (any faster?)
# TODO: document attributes (using Sphinx "#:" comments)
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
    # Marks the method as unable to be used, e.g. if there was a runtime
    # error indicating the method won't work on the current platform.
    unusable = False  # type: bool

    def test(self):  # type: () -> bool
        """Low-impact test that the method is feasible, e.g. command exists."""
        pass

    def get(self, arg):  # type: (str) -> Optional[str]
        """Core logic of the method that performs the lookup."""
        pass


class ArpFile(Method):
    platforms = {"linux"}
    method_type = "ip"
    _path = "/proc/net/arp"

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
    _path = "/sys/class/net/"

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
    _tested_arg = False
    _iface_arg = False
    _arg_regex = r".*ether " + MAC_RE_COLON
    _blank_regex = r"ether " + MAC_RE_COLON

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
    # "ether ": modern Ubuntu, "HWaddr": others
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
    platforms = {"linux", "other"}
    method_type = "iface"
    # "-av": Tru64 system?
    _args = (("", ("ether", r"HWaddr")), ("-a", (r"HWaddr",)),
             ("-v", (r"HWaddr",)), ("-av", (r"Ether",)))
    _args_tested = False
    _good_pair = []

    def test(self):  # type: () -> bool
        return check_command("ifconfig")

    def get(self, arg):  # type: (str) -> Optional[str]
        output = ""
        if not self._args_tested:
            for pair in self._args:
                try:
                    output = _popen("ifconfig", pair[0])
                    self._good_pair = list(pair)
                    if isinstance(self._good_pair[1], str):
                        self._good_pair[1] = self._good_pair[1] + MAC_RE_COLON
                    break
                except CalledProcessError:
                    pass  # TODO: log when debugging
            if not self._good_pair:
                self.unusable = True
                return None
            self._args_tested = True
        if not output:
            output = _popen("ifconfig", self._good_pair[0])
        # Handle the two possible search terms
        if isinstance(self._good_pair[1], tuple):
            for term in self._good_pair[1]:
                regex = term + MAC_RE_COLON
                result = _search(regex, output)
                if result:
                    self._good_pair[1] = regex
                    return result
        else:
            _search(self._good_pair[1], output)


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
        command_output = _popen("arp", arg)
        found = _search(r"\(" + re.escape(arg) + self._regex_std, command_output)
        found = _search(r"\(" + re.escape(arg) + self._regex_darwin, command_output)
        # TODO: finish implementing


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
        return check_path("/proc/net/route")

    def get(self, arg):  # type: (str) -> Optional[str]
        data = _read_file("/proc/net/route")
        if data is not None and len(data) > 1:
            for line in data.split("\n")[1:-1]:
                iface_name, dest = line.split("\t")[:2]
                if dest == "00000000":
                    return iface_name


# TODO: WSL ip route sample (compare to ubuntu)
# TODO: Android ip route sample
class DefaultIfaceRouteCommand(Method):
    platforms = {"linux", "wsl", "other"}
    method_type = "default_iface"

    def test(self):  # type: () -> bool
        return check_command("route")

    def get(self, arg):  # type: (str) -> Optional[str]
        output = _popen("route", "-n")
        # TODO: handle index errors
        return output.partition("0.0.0.0")[2].partition("\n")[0].split()[-1]


# TODO: WSL ip route list sample (compare to ubuntu)
# TODO: Android ip route list sample
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


# TODO: order methods by effectiveness/reliability
#   Use a class attribute maybe? e.g. "score", then sort by score in cache
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


def initialize_method_cache(mac_type):  # type: (str) -> bool
    """Find methods that work.

    Args:
        mac_type: MAC type to initialize the cache for
            Allowed values are: ip | ip4 | ip6 | iface | default_iface
    """
    log.debug("Initializing '%s' method cache (platform: '%s')", mac_type, PLATFORM)

    # Filter methods by the platform we're running on
    platform_methods = [m for m in METHODS  # type: List[type(Method)]
                        if PLATFORM in m.platforms]
    if not platform_methods:
        # If there isn't a method for the current platform,
        # then fallback to the generic platform "other".
        log.warning("No methods for platform '%s'! Your system may not be supported. "
                    "Falling back to platform 'other'", PLATFORM)
        platform_methods = [m for m in METHODS if "other" in m.platforms]
    if DEBUG:
        meth_strs = ", ".join(pm.__name__ for pm in platform_methods)
        log.debug("%d filtered '%s' platform_methods: %s",
                  len(platform_methods), mac_type, meth_strs)

    # Filter methods by the type of MAC we're looking for, such as "ip"
    # for remote host methods or "iface" for local interface methods.
    type_methods = [pm for pm in platform_methods  # type: List[type(Method)]
                    if pm.method_type == mac_type
                    or (pm.method_type == "ip" and mac_type in ["ip4", "ip6"])]
    if not type_methods:
        log.critical("No valid methods found for MAC type '%s'", mac_type)
        return False  # TODO: raise exception?
    if DEBUG:
        type_strs = ", ".join(tm.__name__ for tm in type_methods)
        log.debug("%d filtered '%s' type_methods: %s",
                  len(type_methods), mac_type, type_strs)

    # Determine which methods work on the current system
    tested_methods = []  # type: List[Method]
    for method_class in type_methods:
        method_instance = method_class()  # type: Method
        if method_instance.test():
            tested_methods.append(method_instance)
            # First successful test goes in the cache
            if not CACHE[mac_type]:  # TODO: will mac_type of "ip" break this?
                CACHE[mac_type] = method_instance
        else:
            if DEBUG:
                log.debug("Test failed for method '%s'", method_instance.__class__.__name__)
    if not tested_methods:
        log.critical("All %d '%s' methods failed to test!", len(type_methods), mac_type)
        return False  # TODO: raise exception?
    if DEBUG:
        tested_strs = ", ".join(ts.__class__.__name__ for ts in tested_methods)
        log.debug("%d tested '%s' methods: %s",
                  len(tested_methods), mac_type, tested_strs)
        log.debug("Cached method: %s", CACHE[mac_type].__class__.__name__)

    # TODO: handle method throwing exception, use to mark as non-usable
    #   Do NOT mark return code 1 on a process as non-usable though!
    #   Example of return code 1 on ifconfig from WSL:
    #     Blake:goesc$ ifconfig eth8
    #     eth8: error fetching interface information: Device not found
    #     Blake:goesc$ echo $?
    #     1

    # TODO: log get() failures
    # TODO: exception handling when calling get(), log all exceptions
    #   When exception occurs, remove from cache and reinitialize with next candidate
    #   For example, if get() call to getmac.exe returns 1 then it's not valid

    log.debug("Finished initializing '%s' method cache", mac_type)
    return True
