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
from subprocess import check_output
from shutil import which

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


from .getmac import _read_file, _search, _uuid_convert


# TODO: use self/instance to track state between calls e.g. caching
class Method:
    # linux windows bsd darwin freebsd openbsd
    # TODO: how to handle wsl
    platforms = []
    method_type = ""  # ip, ip4, ip6, iface, default_iface
    net_request = False
    # TODO: __slots__?

    def test(self):
        # type: () -> bool
        pass

    def get(self, arg):
        # type: (str) -> Optional[str]
        pass

# TODO: API to add custom methods at runtime (also to remove methods)


PLATFORM = _SYST.lower()
if PLATFORM == "linux" and "Microsoft" in platform.version():
    PLATFORM = "wsl"


class ArpFile(Method):
    platforms = ["linux"]
    method_type = "ip"
    _path = "/proc/net/arp"

    def test(self):
        return os.path.exists(self._path) and os.access(self._path, os.R_OK)

    def get(self, arg):
        data = _read_file(self._path)
        if data is not None and len(data) > 1:
            # Need a space, otherwise a search for 192.168.16.2
            # will match 192.168.16.254 if it comes first!
            return _search(re.escape(arg) + r" .+" + MAC_RE_COLON, data)
        return None


class SysFile(Method):
    platforms = ["linux"]
    method_type = "iface"
    _path = "/sys/class/net/"

    def test(self):
        # TODO: imperfect, but should work well enough
        return os.path.exists(self._path) and os.access(self._path, os.R_OK)

    def get(self, arg):
        data = _read_file(self._path + arg + "/address")
        # Sometimes this can be empty or a single newline character
        return None if data is not None and len(data) < 17 else data


class UuidLanscan(Method):
    platforms = ["other"]  # TODO
    method_type = "iface"

    def test(self):
        try:
            from uuid import _find_mac
            return bool(which("lanscan", path=PATH))
        except Exception:
            return False

    def get(self, arg):
        from uuid import _find_mac  # type: ignore

        if not PY2:
            iface = bytes(arg, "utf-8")  # type: ignore
        mac = _find_mac("lanscan", "-ai", [arg], lambda i: 0)
        if mac:
            return _uuid_convert(mac)
        return None


METHODS = [
    ArpFile,
    SysFile,
    UuidLanscan
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








