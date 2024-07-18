"""
Get the MAC address of remote hosts or network interfaces.

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
import os
import re
import socket
import struct
import traceback
import warnings
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
)
from subprocess import CalledProcessError
from typing import Dict, List, Optional, Set, Tuple, Type, Union

from . import utils
from .variables import settings, consts, gvars

#: Current version of getmac package
__version__ = "1.0.0a0"


class Method:
    #: Valid platform identifier strings
    VALID_PLATFORM_NAMES: Set[str] = {
        "android",
        "darwin",
        "linux",
        "windows",
        "wsl",
        "openbsd",
        "freebsd",
        "sunos",
        "other",
    }

    #: Platforms supported by a method
    platforms: Set[str] = set()

    #: The type of method, e.g. does it get the MAC of a interface?
    #: Allowed values: {ip, ip4, ip6, iface, default_iface}
    method_type: str = ""

    #: If the method makes a network request as part of the check
    network_request: bool = False

    #: Marks the method as unable to be used, e.g. if there was a runtime
    #: error indicating the method won't work on the current platform.
    unusable: bool = False

    def test(self) -> bool:
        """
        Low-impact test that the method is feasible, e.g. command exists.
        """
        return False  # pragma: no cover

    # TODO: automatically clean MAC on return
    def get(self, arg: str) -> Optional[str]:  # noqa: ARG002
        """
        Core logic of the method that performs the lookup.

        .. warning::
           If the method itself fails to function an exception will be raised!
           (for instance, if some command arguments are invalid, or there's an
           internal error with the command, or a bug in the code).

        Args:
            arg: What the method should get, such as an IP address
                or interface name. In the case of default_iface methods,
                this is not used and defaults to an empty string.

        Returns:
            Lowercase colon-separated MAC address, or None if one could
            not be found.
        """
        return None  # pragma: no cover

    @classmethod
    def __str__(cls) -> str:
        return cls.__name__


# TODO(python3): do we want to keep this around? It calls 3 commands and is
#   quite inefficient. We should just take the methods and use directly.
class UuidArpGetNode(Method):
    platforms = {"linux", "darwin", "sunos", "other"}
    method_type = "ip"

    def test(self) -> bool:
        try:
            from uuid import _arp_getnode  # type: ignore  # noqa: F401

            return True
        except Exception:
            return False

    def get(self, arg: str) -> Optional[str]:
        from uuid import _arp_getnode  # type: ignore

        backup = socket.gethostbyname
        try:
            socket.gethostbyname = lambda x: arg  # noqa: ARG005
            mac1 = _arp_getnode()
            if mac1 is not None:
                mac1 = utils.uuid_convert(mac1)
                mac2 = _arp_getnode()
                mac2 = utils.uuid_convert(mac2)
                if mac1 == mac2:
                    return mac1
        except Exception:
            raise
        finally:
            socket.gethostbyname = backup

        return None


class ArpFile(Method):
    platforms = {"linux"}
    method_type = "ip4"
    _path: str = os.environ.get("ARP_PATH", "/proc/net/arp")

    def test(self) -> bool:
        return utils.check_path(self._path)

    def get(self, arg: str) -> Optional[str]:
        if not arg:
            return None

        data = utils.read_file(self._path)

        if data is None:
            self.unusable = True
            return None

        if data is not None and len(data) > 1:
            # TODO: handle flags column, 0x0 entries are incomplete and should be ignored
            # https://github.com/GhostofGoes/getmac/issues/76
            # Need to get some samples, probably by doing wifi schennigans
            # Not sure if worth addressing for arp command parsers,
            # thought maybe it's a use case for Android? (ArpFile no work?)

            # Need a space, otherwise a search for 192.168.16.2
            # will match 192.168.16.254 if it comes first!
            return utils.search(re.escape(arg) + r" .+" + consts.MAC_RE_COLON, data)

        return None


class ArpFreebsd(Method):
    platforms = {"freebsd"}
    method_type = "ip"

    def test(self) -> bool:
        return utils.check_command("arp")

    def get(self, arg: str) -> Optional[str]:
        regex = r"\(" + re.escape(arg) + r"\)\s+at\s+" + consts.MAC_RE_COLON
        return utils.search(regex, utils.popen("arp", arg))


class ArpOpenbsd(Method):
    platforms = {"openbsd"}
    method_type = "ip"
    _regex: str = r"[ ]+" + consts.MAC_RE_COLON

    def test(self) -> bool:
        return utils.check_command("arp")

    def get(self, arg: str) -> Optional[str]:
        return utils.search(re.escape(arg) + self._regex, utils.popen("arp", "-an"))


class ArpVariousArgs(Method):
    platforms = {"linux", "darwin", "freebsd", "sunos", "other"}
    method_type = "ip"
    _regex_std: str = r"\)\s+at\s+" + consts.MAC_RE_COLON
    _regex_darwin: str = r"\)\s+at\s+" + consts.MAC_RE_SHORT
    _args = (
        ("", True),  # "arp 192.168.1.1"
        # Linux
        ("-an", False),  # "arp -an"
        ("-an", True),  # "arp -an 192.168.1.1"
        # Darwin, WSL, Linux distros???
        ("-a", False),  # "arp -a"
        ("-a", True),  # "arp -a 192.168.1.1"
    )
    _args_tested: bool = False
    _good_pair: Union[Tuple, Tuple[str, bool]] = ()
    _good_regex: str = _regex_darwin if consts.DARWIN else _regex_std

    def test(self) -> bool:
        return utils.check_command("arp")

    def get(self, arg: str) -> Optional[str]:
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

                    command_output = utils.popen("arp", " ".join(cmd_args))
                    self._good_pair = pair_to_test
                    break
                except CalledProcessError as ex:
                    if settings.DEBUG:
                        gvars.log.debug(
                            f"ArpVariousArgs pair test failed for "
                            f"({pair_to_test[0]}, {pair_to_test[1]}): {ex}"
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

            command_output = utils.popen("arp", " ".join(cmd_args))

        escaped = re.escape(arg)
        _good_regex = (
            self._regex_darwin if consts.DARWIN or consts.SOLARIS else self._regex_std
        )  # type: str
        return utils.search(r"\(" + escaped + _good_regex, command_output)


class ArpExe(Method):
    """
    Query the Windows ARP table using ``arp.exe`` to find the MAC address of a remote host.
    This only works for IPv4, since the ARP table is IPv4-only.

    Microsoft Documentation: `arp <https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/arp>`
    """

    platforms = {"windows", "wsl"}
    method_type = "ip4"

    def test(self) -> bool:
        # NOTE: specifying "arp.exe" instead of "arp" lets this work
        # seamlessly on WSL1 as well. On WSL2 it doesn't matter, since
        # it's basically just a Linux VM with some lipstick.
        return utils.check_command("arp.exe")

    def get(self, arg: str) -> Optional[str]:
        return utils.search(consts.MAC_RE_DASH, utils.popen("arp.exe", f"-a {arg}"))


class ArpingHost(Method):
    """
    Use ``arping`` command to determine the MAC of a host.

    Supports three variants of ``arping``

    - "habets" arping by Thomas Habets
        (`GitHub <https://github.com/ThomasHabets/arping>`__)
        On Debian-based distros, ``apt install arping`` will install
        Habets arping.
    - "iputils" arping, from the ``iputils-arping``
        `package <https://packages.debian.org/sid/iputils-arping>`__
    - "busybox" arping, included with BusyBox (a small executable "distro")
        (`further reading <https://boxmatrix.info/wiki/Property:arping>`__)

    BusyBox's arping quite similar to iputils-arping. The arguments for
    our purposes are the same, and the output is also the same.
    There's even a TODO in busybox's arping code referencing iputils arping.
    There are several differences:
    - The return code from bad arguments is 1, not 2 like for iputils-arping
    - The MAC address in output is lowercase (vs. uppercase in iputils-arping)

    This was a pain to obtain samples for busybox on Windows. I recommend
    using WSL and arping'ing the Docker gateway (for WSL2 distros).
    NOTE: it must be run as root using ``sudo busybox arping``.
    """

    platforms = {"linux", "darwin"}
    method_type = "ip4"
    network_request = True
    _is_iputils: bool = True
    _habets_args: str = "-r -C 1 -c 1"
    _iputils_args: str = "-f -c 1"

    def test(self) -> bool:
        return utils.check_command("arping")

    def get(self, arg: str) -> Optional[str]:
        # If busybox or iputils, this will just work, and if host ping fails,
        # then it'll exit with code 1 and this function will return None.
        #
        # If it's Habets, then it'll exit code 1 and have "invalid option"
        # and/or the help message in the output.
        # In the case of Habets, set self._is_iputils to False,
        # then re-try with Habets args.
        try:
            if self._is_iputils:
                command_output = utils.popen("arping", f"{self._iputils_args} {arg}")
                if command_output:
                    return utils.search(
                        r" from %s \[(%s)\]" % (re.escape(arg), consts.MAC_RE_COLON),
                        command_output,
                    )
            else:
                return self._call_habets(arg)
        except CalledProcessError as ex:
            if ex.output and self._is_iputils:
                if isinstance(ex.output, bytes):
                    output = ex.output.decode("utf-8").lower()

                if "habets" in output or "invalid option" in output:
                    if settings.DEBUG:
                        gvars.log.debug("Falling back to Habets arping")
                    self._is_iputils = False
                    try:
                        return self._call_habets(arg)
                    except CalledProcessError:
                        pass

        return None

    def _call_habets(self, arg: str) -> Optional[str]:
        command_output = utils.popen("arping", f"{self._habets_args} {arg}")
        if command_output:
            return command_output.strip()
        else:
            return None


class CtypesHost(Method):
    """
    Uses ``SendARP`` from the Windows ``Iphlpapi`` to get the MAC address
    of a remote IPv4 host.

    Microsoft Documentation: `SendARP function (iphlpapi.h) <https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-sendarp>`__
    """

    platforms = {"windows"}
    method_type = "ip4"
    network_request = True

    def test(self) -> bool:
        try:
            return ctypes.windll.wsock32.inet_addr(b"127.0.0.1") > 0  # type: ignore
        except Exception:
            return False

    def get(self, arg: str) -> Optional[str]:
        try:
            # Convert to bytes on Python 3+ (Fixes GitHub issue #7)
            inetaddr = ctypes.windll.wsock32.inet_addr(arg.encode())  # type: ignore
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

        # https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-sendarp
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


class IpNeighborShow(Method):
    platforms = {"linux", "other"}
    method_type = "ip"  # IPv6 and IPv4

    def test(self) -> bool:
        return utils.check_command("ip")

    def get(self, arg: str) -> Optional[str]:
        output = utils.popen("ip", f"neighbor show {arg}")
        if not output:
            return None

        try:
            # NOTE: the space prevents accidental matching of partial IPs
            return (
                output.partition(arg + " ")[2].partition("lladdr")[2].strip().split()[0]
            )
        except IndexError as ex:
            gvars.log.debug(f"IpNeighborShow failed with exception: {ex}")
            return None


class SysIfaceFile(Method):
    platforms = {"linux", "wsl"}
    method_type = "iface"
    _path: str = "/sys/class/net/"

    def test(self) -> bool:
        # Imperfect, but should work well enough
        return utils.check_path(self._path)

    def get(self, arg: str) -> Optional[str]:
        data = utils.read_file(self._path + arg + "/address")

        # NOTE: if "/sys/class/net/" exists, but interface file doesn't,
        # then that means the interface doesn't exist
        # Sometimes this can be empty or a single newline character
        return None if data is not None and len(data) < 17 else data


class UuidLanscan(Method):
    platforms = {"other"}
    method_type = "iface"

    def test(self) -> bool:
        try:
            from uuid import _find_mac  # type: ignore  # noqa: F401

            return utils.check_command("lanscan")
        except Exception:
            return False

    def get(self, arg: str) -> Optional[str]:
        from uuid import _find_mac  # type: ignore

        mac = _find_mac("lanscan", "-ai", [arg.encode()], lambda i: 0)  # noqa: ARG005

        if mac:
            return utils.uuid_convert(mac)

        return None


class FcntlIface(Method):
    platforms = {"linux", "wsl"}
    method_type = "iface"

    def test(self) -> bool:
        try:
            import fcntl  # noqa: F401

            return True
        except Exception:  # Broad except to handle unknown effects
            return False

    def get(self, arg: str) -> Optional[str]:
        import fcntl

        encoded_arg = arg.encode()

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # 0x8927 = SIOCGIFADDR
        info = fcntl.ioctl(  # type: ignore
            s.fileno(), 0x8927, struct.pack("256s", encoded_arg[:15])
        )

        return ":".join(["%02x" % ord(chr(char)) for char in info[18:24]])


class GetmacExe(Method):
    """
    Uses Windows-builtin ``getmac.exe`` to get a interface's MAC address.

    Microsoft Documentation: `getmac <https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/getmac>`__
    """

    platforms = {"windows"}
    method_type = "iface"
    _regexes: List[Tuple[str, str]] = [
        # Connection Name
        (r"\r\n", r".*" + consts.MAC_RE_DASH + r".*\r\n"),
        # Network Adapter (the human-readable name)
        (r"\r\n.*", r".*" + consts.MAC_RE_DASH + r".*\r\n"),
    ]
    _champ: Union[tuple, Tuple[str, str]] = ()

    def test(self) -> bool:
        # NOTE: the scripts from this library (getmac) are excluded from the
        # path used for checking variables, in getmac.getmac.PATH (defined
        # at the top of this file). Otherwise, this would get messy quickly :)
        return utils.check_command("getmac.exe")

    def get(self, arg: str) -> Optional[str]:
        try:
            # /nh: Suppresses table headers
            # /v:  Verbose
            command_output = utils.popen("getmac.exe", "/NH /V")
        except CalledProcessError as ex:
            # This shouldn't cause an exception if it's valid command
            gvars.log.error(f"getmac.exe failed, marking unusable. Exception: {ex}")
            self.unusable = True
            return None

        if self._champ:
            return utils.search(self._champ[0] + arg + self._champ[1], command_output)

        for pair in self._regexes:
            result = utils.search(pair[0] + arg + pair[1], command_output)
            if result:
                self._champ = pair
                return result

        return None


class IpconfigExe(Method):
    """
    Uses ``ipconfig.exe`` to find interface MAC addresses on Windows.

    This is generally pretty reliable and works across a wide array of
    versions and releases. I'm not sure if it works pre-XP though.

    Microsoft Documentation: `ipconfig <https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ipconfig>`__
    """

    platforms = {"windows"}
    method_type = "iface"
    _regex: str = (
        r"(?:\n?[^\n]*){1,8}Physical Address[ .:]+" + consts.MAC_RE_DASH + r"\r\n"
    )

    def test(self) -> bool:
        return utils.check_command("ipconfig.exe")

    def get(self, arg: str) -> Optional[str]:
        return utils.search(arg + self._regex, utils.popen("ipconfig.exe", "/all"))


class WmicExe(Method):
    """
    Use ``wmic.exe`` on Windows to find the MAC address of a network interface.

    Microsoft Documentation: `wmic <https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wmic>`__

    .. warning::
       WMIC is deprecated as of Windows 10 21H1. This method may not work on
       Windows 11 and may stop working at some point on Windows 10 (unlikely,
       but possible).
    """

    platforms = {"windows"}
    method_type = "iface"

    def test(self) -> bool:
        return utils.check_command("wmic.exe")

    def get(self, arg: str) -> Optional[str]:
        command_output = utils.popen(
            "wmic.exe",
            f'nic where "NetConnectionID = \'{arg}\'" get "MACAddress" /value',
        )

        # Negative: "No Instance(s) Available"
        # Positive: "MACAddress=00:FF:E7:78:95:A0"
        # NOTE: .partition() always returns 3 parts,
        # therefore it won't cause an IndexError
        return command_output.strip().partition("=")[2]


class DarwinNetworksetupIface(Method):
    """
    Use ``networksetup`` on MacOS (Darwin) to get the MAC address of a specific interface.

    I think that this is or was a BSD utility, but I haven't seen it on other BSDs
    (FreeBSD, OpenBSD, etc.). So, I'm treating it as a Darwin-specific utility
    until further notice. If you know otherwise, please open a PR :)

    If the command is present, it should always work, though naturally that is contingent
    upon the whims of Apple in newer MacOS releases.

    Man page: `networksetup (8) <https://www.manpagez.com/man/8/networksetup/>`__
    """

    platforms = {"darwin"}
    method_type = "iface"

    def test(self) -> bool:
        return utils.check_command("networksetup")

    def get(self, arg: str) -> Optional[str]:
        command_output = utils.popen("networksetup", f"-getmacaddress {arg}")
        return utils.search(consts.MAC_RE_COLON, command_output)


# This only took 15-20 hours of throwing my brain against a wall multiple times
# over the span of 1-2 years to figure out. It works for almost all conceivable
# output from "ifconfig", and probably netstat too. It can probably be made more
# efficient by someone who actually knows how to write regex.
# [: ]\s?(?:flags=|\s).*?(?:(?:\w+[: ]\s?flags=)|\s(?:ether|address|HWaddr|hwaddr|lladdr)[ :]?\s?([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}))  # noqa: E501
IFCONFIG_REGEX = (
    r"[: ]\s?(?:flags=|\s).*?(?:"
    r"(?:\w+[: ]\s?flags=)|"  # Prevent interfaces w/o a MAC from matching
    r"\s(?:ether|address|HWaddr|hwaddr|lladdr)[ :]?\s?"  # Handle various prefixes
    r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}))"  # Match the MAC
)


def _parse_ifconfig(iface: str, command_output: str) -> Optional[str]:
    if not iface or not command_output:
        return None

    # Sanity check on input e.g. if user does "eth0:" as argument
    iface = iface.strip(":")

    # "(?:^|\s)": prevent an input of "h0" from matching on "eth0"
    search_re = r"(?:^|\s)" + iface + IFCONFIG_REGEX

    return utils.search(search_re, command_output, flags=re.DOTALL)


class IfconfigWithIfaceArg(Method):
    """
    ``ifconfig`` command with the interface name as an argument
    (e.g. ``ifconfig eth0``).
    """

    platforms = {"linux", "wsl", "freebsd", "openbsd", "other"}
    method_type = "iface"

    def test(self) -> bool:
        return utils.check_command("ifconfig")

    def get(self, arg: str) -> Optional[str]:
        try:
            command_output = utils.popen("ifconfig", arg)
        except CalledProcessError as err:
            # Return code of 1 means interface doesn't exist
            if err.returncode == 1:
                return None
            else:
                raise err  # this will cause another method to be used

        return _parse_ifconfig(arg, command_output)


# TODO: combine this with IfconfigWithArg/IfconfigNoArg
#       (need to do live testing on Darwin)
class IfconfigEther(Method):
    platforms = {"darwin"}
    method_type = "iface"
    _tested_arg: bool = False
    _iface_arg: bool = False

    def test(self) -> bool:
        return utils.check_command("ifconfig")

    def get(self, arg: str) -> Optional[str]:
        # Check if this version of "ifconfig" accepts an interface argument
        command_output = ""

        if not self._tested_arg:
            try:
                command_output = utils.popen("ifconfig", arg)
                self._iface_arg = True
            except CalledProcessError:
                self._iface_arg = False
            self._tested_arg = True

        if self._iface_arg and not command_output:  # Don't repeat work on first run
            command_output = utils.popen("ifconfig", arg)
        else:
            command_output = utils.popen("ifconfig", "")

        return _parse_ifconfig(arg, command_output)


# TODO: create new methods, IfconfigNoArgs and IfconfigVariousArgs
# TODO: unit tests
class IfconfigOther(Method):
    """
    Wild 'Shot in the Dark' attempt at ``ifconfig`` for unknown platforms.
    """

    platforms = {"linux", "other"}
    method_type = "iface"
    # "-av": Tru64 system?
    _args = (
        ("", (r"(?::| ).*?\sether\s", r"(?::| ).*?\sHWaddr\s")),
        ("-a", r".*?HWaddr\s"),
        ("-v", r".*?HWaddr\s"),
        ("-av", r".*?Ether\s"),
    )
    _args_tested: bool = False
    _good_pair: List[Union[str, Tuple[str, str]]] = []

    def test(self) -> bool:
        return utils.check_command("ifconfig")

    def get(self, arg: str) -> Optional[str]:
        if not arg:
            return None

        # Cache output from testing command so first call isn't wasted
        command_output = ""

        # Test which arguments are valid to the command
        if not self._args_tested:
            for pair_to_test in self._args:
                try:
                    command_output = utils.popen("ifconfig", pair_to_test[0])
                    self._good_pair = list(pair_to_test)  # type: ignore
                    if isinstance(self._good_pair[1], str):
                        self._good_pair[1] += consts.MAC_RE_COLON
                    break
                except CalledProcessError as ex:
                    if settings.DEBUG:
                        gvars.log.debug(
                            f"IfconfigOther pair test failed for "
                            f"({pair_to_test[0]}, {pair_to_test[1]}): {ex}"
                        )

            if not self._good_pair:
                self.unusable = True
                return None

            self._args_tested = True

        if not command_output and isinstance(self._good_pair[0], str):
            command_output = utils.popen("ifconfig", self._good_pair[0])

        # Handle the two possible search terms
        if isinstance(self._good_pair[1], tuple):
            for term in self._good_pair[1]:
                regex = term + consts.MAC_RE_COLON
                result = utils.search(re.escape(arg) + regex, command_output)

                if result:
                    # changes type from tuple to str, so the else statement
                    # will be hit on the next call to this method
                    self._good_pair[1] = regex
                    return result
            return None
        else:
            return utils.search(re.escape(arg) + self._good_pair[1], command_output)


class NetstatIface(Method):
    platforms = {"linux", "wsl", "other"}
    method_type = "iface"

    # ".*?": non-greedy
    # https://docs.python.org/3/howto/regex.html#greedy-versus-non-greedy
    _regexes: List[str] = [
        r": .*?ether " + consts.MAC_RE_COLON,
        r": .*?HWaddr " + consts.MAC_RE_COLON,
        # Ubuntu 12.04 and other older kernels
        r" .*?Link encap:Ethernet  HWaddr " + consts.MAC_RE_COLON,
    ]
    _working_regex: str = ""

    def test(self) -> bool:
        return utils.check_command("netstat")

    # TODO: consolidate the parsing logic between IfconfigOther and netstat
    def get(self, arg: str) -> Optional[str]:
        # NOTE: netstat and ifconfig pull from the same kernel source and
        # therefore have the same output format on the same platform.
        command_output = utils.popen("netstat", "-iae")
        if not command_output:
            gvars.log.warning("no netstat output, marking unusable")
            self.unusable = True
            return None

        if self._working_regex:
            # Use regex that worked previously. This can still return None in
            # the case of interface not existing, but at least it's a bit faster.
            return utils.search(
                arg + self._working_regex, command_output, flags=re.DOTALL
            )

        # See if either regex matches
        for regex in self._regexes:
            result = utils.search(arg + regex, command_output, flags=re.DOTALL)
            if result:
                self._working_regex = regex
                return result

        return None


# TODO: Add to IpLinkIface
# TODO: New method for "ip addr"? (this would be useful for CentOS and others as a fallback)
# (r"state UP.*\n.*ether " + consts.MAC_RE_COLON, 0, "ip", ["link","addr"]),
# (r"wlan.*\n.*ether " + consts.MAC_RE_COLON, 0, "ip", ["link","addr"]),
# (r"ether " + consts.MAC_RE_COLON, 0, "ip", ["link","addr"]),
# _regexes = (
#     r".*\n.*link/ether " + consts.MAC_RE_COLON,
#     # Android 6.0.1+ (and likely other platforms as well)
#     r"state UP.*\n.*ether " + consts.MAC_RE_COLON,
#     r"wlan.*\n.*ether " + consts.MAC_RE_COLON,
#     r"ether " + consts.MAC_RE_COLON,
# )  # type: Tuple[str, str, str, str]


class IpLinkIface(Method):
    platforms = {"linux", "wsl", "android", "other"}
    method_type = "iface"
    _regex: str = r".*\n.*link/ether " + consts.MAC_RE_COLON
    _tested_arg: bool = False
    _iface_arg: bool = False

    def test(self) -> bool:
        return utils.check_command("ip")

    def get(self, arg: str) -> Optional[str]:
        # Check if this version of "ip link" accepts an interface argument
        # Not accepting one is a quirk of older versions of 'iproute2'
        # TODO: is it "ip link <arg>" on some platforms and "ip link show <arg>" on others?
        command_output = ""

        if not self._tested_arg:
            try:
                command_output = utils.popen("ip", "link show " + arg)
                self._iface_arg = True
            except CalledProcessError as err:
                # Output: 'Command "eth0" is unknown, try "ip link help"'
                if err.returncode != 255:
                    raise err
            self._tested_arg = True

        if self._iface_arg:
            if not command_output:  # Don't repeat work on first run
                command_output = utils.popen("ip", "link show " + arg)
            return utils.search(arg + self._regex, command_output)
        else:
            # TODO: improve this regex to not need extra portion for no arg
            command_output = utils.popen("ip", "link")
            return utils.search(arg + r":" + self._regex, command_output)


class DefaultIfaceLinuxRouteFile(Method):
    """
    Get the default interface by parsing the ``/proc/net/route`` file.

    This is the same source as the ``route`` command, however it's much
    faster to read this file than to call ``route``. If it fails for whatever
    reason, we can fall back on the system commands (e.g for a platform that
    has a route command, but doesn't use ``/proc``, such as BSD-based platforms).
    """

    platforms = {"linux", "wsl"}
    method_type = "default_iface"

    def test(self) -> bool:
        return utils.check_path("/proc/net/route")

    def get(self, arg: str = "") -> Optional[str]:  # noqa: ARG002
        data = utils.read_file("/proc/net/route")

        if data is not None and len(data) > 1:
            for line in data.split("\n")[1:-1]:
                line = line.strip()
                if not line:
                    continue

                # Some have tab separators, some have spaces
                if "\t" in line:
                    sep = "\t"
                else:
                    sep = "    "

                iface_name, dest = line.split(sep)[:2]

                if dest == "00000000":
                    return iface_name

            if settings.DEBUG:
                gvars.log.debug(
                    "Failed to find default interface in data from "
                    "'/proc/net/route', no destination of '00000000' was found"
                )
        elif settings.DEBUG:
            gvars.log.warning("No data from /proc/net/route")

        return None


class DefaultIfaceRouteCommand(Method):
    platforms = {"linux", "wsl", "other"}
    method_type = "default_iface"

    def test(self) -> bool:
        return utils.check_command("route")

    def get(self, arg: str = "") -> Optional[str]:
        output = utils.popen("route", "-n")

        try:
            return (
                output.partition("0.0.0.0")[2]  # noqa: S104
                .partition("\n")[0]
                .split()[-1]
            )
        except IndexError as ex:  # index errors means no default route in output?
            gvars.log.debug(f"DefaultIfaceRouteCommand failed for {arg}: {ex}")
            return None


class DefaultIfaceRouteGetCommand(Method):
    platforms = {"darwin", "freebsd", "other"}
    method_type = "default_iface"

    def test(self) -> bool:
        return utils.check_command("route")

    def get(self, arg: str = "") -> Optional[str]:
        output = utils.popen("route", "get default")

        if not output:
            return None

        try:
            return output.partition("interface: ")[2].strip().split()[0].strip()
        except IndexError as ex:
            gvars.log.debug(f"DefaultIfaceRouteCommand failed for {arg}: {ex}")
            return None


class DefaultIfaceIpRoute(Method):
    # NOTE: this is slightly faster than "route" since
    # there is less output than "route -n"
    platforms = {"linux", "wsl", "other"}
    method_type = "default_iface"

    def test(self) -> bool:
        return utils.check_command("ip")

    def get(self, arg: str = "") -> Optional[str]:  # noqa: ARG002
        output = utils.popen("ip", "route list 0/0")

        if not output:
            if settings.DEBUG:
                gvars.log.debug("DefaultIfaceIpRoute failed: no output")
            return None

        return output.partition("dev")[2].partition("proto")[0].strip()


class DefaultIfaceOpenBsd(Method):
    platforms = {"openbsd"}
    method_type = "default_iface"

    def test(self) -> bool:
        return utils.check_command("route")

    def get(self, arg: str = "") -> Optional[str]:  # noqa: ARG002
        output = utils.popen("route", "-nq show -inet -gateway -priority 1")
        return output.partition("127.0.0.1")[0].strip().rpartition(" ")[2]


class DefaultIfaceFreeBsd(Method):
    platforms = {"freebsd"}
    method_type = "default_iface"

    def test(self) -> bool:
        return utils.check_command("netstat")

    def get(self, arg: str = "") -> Optional[str]:  # noqa: ARG002
        output = utils.popen("netstat", "-r")
        return utils.search(r"default[ ]+\S+[ ]+\S+[ ]+(\S+)[\r\n]+", output)


# TODO: order methods by effectiveness/reliability
#   Use a class attribute maybe? e.g. "score", then sort by score in cache
METHODS = [
    # NOTE: CtypesHost is faster than ArpExe because of sub-process startup times :)
    CtypesHost,
    ArpFile,
    ArpingHost,
    SysIfaceFile,
    FcntlIface,
    UuidLanscan,
    GetmacExe,
    IpconfigExe,
    WmicExe,
    ArpExe,
    DarwinNetworksetupIface,
    ArpFreebsd,
    ArpOpenbsd,
    IfconfigWithIfaceArg,
    IfconfigEther,
    IfconfigOther,
    IpLinkIface,
    NetstatIface,
    IpNeighborShow,
    ArpVariousArgs,
    UuidArpGetNode,
    DefaultIfaceLinuxRouteFile,
    DefaultIfaceIpRoute,
    DefaultIfaceRouteCommand,
    DefaultIfaceRouteGetCommand,
    DefaultIfaceOpenBsd,
    DefaultIfaceFreeBsd,
]  # type: List[Type[Method]]

# TODO: move to gvars class? gotta love import loops with type annotations
# Primary method to use for a given method type
METHOD_CACHE: Dict[str, Optional[Method]] = {
    "ip4": None,
    "ip6": None,
    "iface": None,
    "default_iface": None,
}


# Order of methods is determined by:
#   Platform + version
#   Performance (file read > command)
#   Reliability (how well I know/understand the command to work)
FALLBACK_CACHE: Dict[str, List[Method]] = {
    "ip4": [],
    "ip6": [],
    "iface": [],
    "default_iface": [],
}


def get_method_by_name(method_name: str) -> Optional[Type[Method]]:
    for method in METHODS:
        if method.__name__.lower() == method_name.lower():
            return method

    return None


def get_instance_from_cache(method_type: str, method_name: str) -> Optional[Method]:
    """
    Get the class for a named :class:`~getmac.getmac.Method` from the caches.

    :data:`~getmac.getmac.METHOD_CACHE` is checked first, and if that fails,
    then any entries in :data:`~getmac.getmac.FALLBACK_CACHE` are checked.
    If both fail, :obj:`None` is returned.

    Args:
        method_type: what cache should be checked.
            Allowed values are:  ``ip4`` | ``ip6`` | ``iface`` | ``default_iface``
        method_name: name of the method to look for

    Returns:
        The cached method, or :obj:`None` if the method was not found
    """

    if str(METHOD_CACHE[method_type]) == method_name:
        return METHOD_CACHE[method_type]

    for f_meth in FALLBACK_CACHE[method_type]:
        if str(f_meth) == method_name:
            return f_meth

    return None


def _swap_method_fallback(method_type: str, swap_with: str) -> bool:
    if str(METHOD_CACHE[method_type]) == swap_with:
        return True

    found = None  # type: Optional[Method]
    for f_meth in FALLBACK_CACHE[method_type]:
        if str(f_meth) == swap_with:
            found = f_meth
            break

    if not found:
        return False

    curr = METHOD_CACHE[method_type]
    FALLBACK_CACHE[method_type].remove(found)
    METHOD_CACHE[method_type] = found
    FALLBACK_CACHE[method_type].insert(0, curr)  # type: ignore

    return True


def _warn_critical(err_msg: str) -> None:
    gvars.log.critical(err_msg)
    warnings.warn(  # noqa: B028
        f"{err_msg}. NOTICE: this warning my turn into a raised exception in a future release",
        RuntimeWarning,
    )


def initialize_method_cache(method_type: str, network_request: bool = True) -> bool:
    """
    Initialize the method cache for the given method type.

    Args:
        method_type: method type to initialize the cache for.
            Allowed values are:  ``ip4`` | ``ip6`` | ``iface`` | ``default_iface``
        network_request: if methods that make network requests should be included
            (those methods that have the attribute ``network_request`` set to :obj:`True`)

    Returns:
        If the cache was initialized successfully
    """
    if METHOD_CACHE.get(method_type):
        if settings.DEBUG:
            gvars.log.debug(
                f"Method cache already initialized for method type '{method_type}'"
            )
        return True

    gvars.log.debug(
        f"Initializing '{method_type}' method cache (platform: '{consts.PLATFORM}')"
    )

    if settings.OVERRIDE_PLATFORM:
        gvars.log.warning(
            f"Platform override is set, using '{settings.OVERRIDE_PLATFORM}' as platform "
            f"instead of detected platform '{consts.PLATFORM}'"
        )
        platform = settings.OVERRIDE_PLATFORM
    else:
        platform = consts.PLATFORM

    if settings.DEBUG >= 4:
        meth_strs = ", ".join(m.__name__ for m in METHODS)
        gvars.log.debug(f"{len(METHODS)} methods available: {meth_strs}")

    # Filter methods by the type of MAC we're looking for, such as "ip"
    # for remote host methods or "iface" for local interface methods.
    type_methods = [
        method
        for method in METHODS
        if (method.method_type != "ip" and method.method_type == method_type)
        # Methods with a type of "ip" can handle both IPv4 and IPv6
        or (method.method_type == "ip" and method_type in ["ip4", "ip6"])
    ]  # type: List[Type[Method]]

    if not type_methods:
        _warn_critical(f"No valid methods matching MAC type '{method_type}'")
        return False

    if settings.DEBUG >= 2:
        type_strs = ", ".join(tm.__name__ for tm in type_methods)
        gvars.log.debug(
            f"{len(type_methods)} type-filtered methods for '{method_type}': {type_strs}"
        )

    # Filter methods by the platform we're running on
    platform_methods = [
        method for method in type_methods if platform in method.platforms
    ]  # type: List[Type[Method]]

    if not platform_methods:
        # If there isn't a method for the current platform,
        # then fallback to the generic platform "other".
        warn_msg = (
            f"No methods for platform '{platform}'! "
            "Your system may not be supported. "
            "Falling back to platform 'other'."
        )
        gvars.log.warning(warn_msg)
        warnings.warn(warn_msg, RuntimeWarning, stacklevel=2)
        platform_methods = [
            method for method in type_methods if "other" in method.platforms
        ]

    if settings.DEBUG >= 2:
        plat_strs = ", ".join(pm.__name__ for pm in platform_methods)
        gvars.log.debug(
            f"{len(platform_methods)} platform-filtered methods for '{platform}' "
            f"(method_type='{method_type}'): {plat_strs}"
        )

    if not platform_methods:
        _warn_critical(
            f"No valid methods found for MAC type '{method_type}' and platform '{platform}'"
        )
        return False

    filtered_methods = platform_methods  # type: List[Type[Method]]

    # If network_request is False, then remove any methods that have network_request=True
    if not network_request:
        filtered_methods = [m for m in platform_methods if not m.network_request]

    # Determine which methods work on the current system
    tested_methods = []  # type: List[Method]

    for method_class in filtered_methods:
        method_instance = method_class()  # type: Method
        try:
            test_result = method_instance.test()
        except Exception:
            test_result = False
        if test_result:
            tested_methods.append(method_instance)
            # First successful test goes in the cache
            if not METHOD_CACHE[method_type]:
                METHOD_CACHE[method_type] = method_instance
        elif settings.DEBUG:
            gvars.log.debug(f"Test failed for method '{method_instance!s}'")

    if not tested_methods:
        _warn_critical(
            f"All {len(filtered_methods)} '{method_type}' methods failed to test!"
        )
        return False

    if settings.DEBUG >= 2:
        tested_strs = ", ".join(str(ts) for ts in tested_methods)
        gvars.log.debug(
            f"{len(tested_methods)} tested methods for '{method_type}': {tested_strs}"
        )

    # Populate fallback cache with all the tested methods, minus the currently active method
    if METHOD_CACHE[method_type] and METHOD_CACHE[method_type] in tested_methods:
        tested_methods.remove(METHOD_CACHE[method_type])  # type: ignore

    FALLBACK_CACHE[method_type] = tested_methods

    if settings.DEBUG:
        gvars.log.debug(
            "Current method cache: %s",
            str({k: str(v) for k, v in METHOD_CACHE.items()}),
        )
        gvars.log.debug(
            "Current fallback cache: %s",
            str({k: str(v) for k, v in FALLBACK_CACHE.items()}),
        )
    gvars.log.debug(f"Finished initializing '{method_type}' method cache")

    return True


def _remove_unusable(method: Method, method_type: str) -> Optional[Method]:
    if not FALLBACK_CACHE[method_type]:
        gvars.log.warning(f"No fallback method for unusable method '{method!s}'!")
        METHOD_CACHE[method_type] = None
    else:
        METHOD_CACHE[method_type] = FALLBACK_CACHE[method_type].pop(0)
        gvars.log.warning(
            f"Falling back to '{METHOD_CACHE[method_type]!s}' for unusable method '{method!s}'"
        )

    return METHOD_CACHE[method_type]


def _attempt_method_get(method: Method, method_type: str, arg: str) -> Optional[str]:
    """
    Attempt to use methods, and if they fail, fallback to the next method in the cache.
    """
    if not METHOD_CACHE[method_type] and not FALLBACK_CACHE[method_type]:
        _warn_critical(f"No usable methods found for MAC type '{method_type}'")
        return None

    if settings.DEBUG:
        gvars.log.debug(
            f"Attempting get() (method='{method!s}', method_type='{method_type}', arg='{arg}')"
        )

    result = None
    try:
        result = method.get(arg)
    except CalledProcessError as ex:
        # Don't mark return code 1 on a process as unusable!
        #   Example of return code 1 on ifconfig from WSL:
        #     Blake:goesc$ ifconfig eth8
        #     eth8: error fetching interface information: Device not found
        #     Blake:goesc$ echo $?
        #     1
        # Methods where an exit code of 1 makes it invalid should handle the
        # CalledProcessError, inspect the return code, and set self.unusable = True
        if ex.returncode != 1:
            gvars.log.warning(
                f"Cached Method '{method!s}' failed for '{method_type}' lookup with process exit "
                f"code '{ex.returncode}' != 1, marking unusable. Exception: {ex}"
            )
            method.unusable = True
    except Exception as ex:
        gvars.log.warning(
            f"Cached Method '{method!s}' failed for '{method_type}' "
            f"lookup with unhandled exception: {ex}"
        )
        method.unusable = True

    # When an unhandled exception occurs (or exit code other than 1), remove
    # the method from the cache and reinitialize with next candidate.
    if not result and method.unusable:
        new_method = _remove_unusable(method, method_type)

        if not new_method:
            return None

        return _attempt_method_get(new_method, method_type, arg)

    return result


def get_by_method(
    method_type: str, arg: str = "", network_request: bool = True
) -> Optional[str]:
    """
    Query for a MAC using a specific method.

    Args:
        method_type: the type of lookup being performed.
            Allowed values are: ``ip4``, ``ip6``, ``iface``, ``default_iface``
        arg: Argument to pass to the method, e.g. an interface name or IP address
        network_request: if methods that make network requests should be included
            (those methods that have the attribute ``network_request`` set to :obj:`True`)

    Returns:
        The MAC address string, or :obj:`None` if the operation failed
    """
    if not arg and method_type != "default_iface":
        gvars.log.error(f"Empty arg for method '{method_type}' (raw value: {arg!r})")
        return None

    if settings.FORCE_METHOD:
        gvars.log.warning(
            f"Forcing method '{settings.FORCE_METHOD}' to be used for "
            f"'{method_type}' lookup (arg: '{arg}')"
        )

        forced_method = get_method_by_name(settings.FORCE_METHOD)

        if not forced_method:
            gvars.log.error(
                f"Invalid FORCE_METHOD method name '{settings.FORCE_METHOD}'"
            )
            return None

        return forced_method().get(arg)

    method = METHOD_CACHE.get(method_type)  # type: Optional[Method]

    if not method:
        # Initialize the cache if it hasn't been already
        if not initialize_method_cache(method_type, network_request):
            gvars.log.error(
                f"Failed to initialize method cache for method '{method_type}' (arg: '{arg}')"
            )
            return None

        method = METHOD_CACHE[method_type]

    if not method:
        gvars.log.error(
            f"Initialization failed for method '{method_type}'. "
            f"It may not be supported on this platform or another issue occurred."
        )
        return None

    # TODO: add a "net_ok" argument, check network_request attribute
    #   on method in CACHE, if not then keep checking for method in
    #   FALLBACK_CACHE that has network_request.
    result = _attempt_method_get(method, method_type, arg)

    # Log normal get() failures if debugging is enabled
    if settings.DEBUG and not result:
        gvars.log.debug(f"Method '{method!s}' failed for '{method_type}' lookup")

    return result


def get_mac_address(
    interface: Union[str, bytes, None] = None,
    ip: Union[
        str, bytes, IPv4Address, IPv4Interface, IPv6Address, IPv6Interface, None
    ] = None,
    ip6: Union[str, bytes, IPv6Address, IPv6Interface, None] = None,
    hostname: Union[str, bytes, None] = None,
    network_request: bool = True,
) -> Optional[str]:
    """
    Get a MAC from a local interface or remote host.

    If you want to be pedantic, this is (probably)
    a unicast IEEE 802 MAC-48 address.

    Only ONE of the first four arguments may be used
    (``interface``,``ip``, ``ip6``, or ``hostname``).
    If none of the arguments are selected, the default network interface for
    the system will be used.

    .. warning::
       In getmac 1.0.0, exceptions will be raised if the method cache initialization fails
       (in other words, if there are no valid methods found for the type of MAC requested).

    .. note::
       ``"localhost"`` or ``"127.0.0.1"`` will always return ``"00:00:00:00:00:00"``

    .. note::
       It is assumed that you are using Ethernet or Wi-Fi. While other protocols
       such as Bluetooth may work, this has not been tested and should not be
       relied upon. If you need this functionality, please open an issue
       (or better yet, a Pull Request ;))!

    .. note::
       Exceptions raised by methods are handled silently and returned as :obj:`None`.

    Args:
        interface: Name of a local network interface (e.g "Ethernet 3", "eth0", "ens32")
        ip: Canonical dotted decimal IPv4 address of a remote host (e.g ``192.168.0.1``),
            or a :mod:`ipaddress` object (:class:`~ipaddress.IPv4Address` or
            :class:`~ipaddress.IPv4Interface`). This will also accept
            :class:`~ipaddress.IPv6Address` and :class:`~ipaddress.IPv6Interface`,
            and treat them as if ``ip6`` argument was set instead.
        ip6: Canonical shortened IPv6 address of a remote host (e.g ``ff02::1:ffe7:7f19``),
            or a :mod:`ipaddress` object (:class:`~ipaddress.IPv6Address`
            and :class:`~ipaddress.IPv6Interface`).
        hostname: DNS hostname of a remote host (e.g "router1.mycorp.com", "localhost")
        network_request: If network requests should be made when attempting to find the
            MAC of a remote host. If the ``arping`` command is available, this will be used.
            If not, a UDP packet will be sent to the remote host to populate
            the ARP/NDP tables for IPv4/IPv6. The port this packet is sent to can
            be configured using the setting ``getmac.settings.PORT``.

    Returns:
        Lowercase colon-separated MAC address, or :obj:`None` if one could not be
        found or there was an error.
    """

    # If debugging, start the timer
    if settings.DEBUG:
        import timeit

        start_time = timeit.default_timer()

    # Convert bytes to str
    if isinstance(interface, bytes):
        interface = interface.decode("utf-8")
    if isinstance(ip, bytes):
        ip = ip.decode("utf-8")
    if isinstance(ip6, bytes):
        ip6 = ip6.decode("utf-8")
    if isinstance(hostname, bytes):
        hostname = hostname.decode("utf-8")

    # Handle ipaddress objects
    # "is not None" check makes mypy happier
    if ip is not None and not isinstance(ip, str):
        # NOTE: IPv4Interface check must be done first,
        # since it's a sub-class of IPv4Address.
        if isinstance(ip, IPv4Interface):
            ip = str(ip.ip)
        elif isinstance(ip, IPv4Address):
            ip = str(ip)
        elif isinstance(ip, IPv4Network):
            raise ValueError(
                "IPv4Network objects are not supported. getmac needs a host address, "
                "not a network. Try IPv4Address or IPv4Interface instead."
            )
        # If IPv6 objects are passed to the ip argument,
        # convert them to strings and assign to ip6, and
        # unassign ip.
        # NOTE: IPv6Interface check must be done first,
        # since it's a sub-class of IPv6Address.
        elif isinstance(ip, IPv6Interface):
            ip6 = str(ip.ip)
            ip = None
        elif isinstance(ip, IPv6Address):
            ip6 = str(ip)
            ip = None
        elif isinstance(ip, IPv6Network):
            raise ValueError(
                "IPv6Network objects are not supported. getmac needs a host address, "
                "not a network. Try IPv6Address or IPv6Interface instead."
            )
        else:
            raise ValueError(
                f"Unknown type for 'ip' argument: '{ip.__class__.__name__}'"
            )

    if (hostname and hostname == "localhost") or (ip and ip == "127.0.0.1"):
        return "00:00:00:00:00:00"

    # Resolve hostname to an IP address
    if hostname:
        # Exceptions will be handled silently and returned as a None
        try:
            # TODO: can this return a IPv6 address? If so, handle that!
            ip = socket.gethostbyname(hostname)
        except Exception as ex:
            gvars.log.error(f"Could not resolve hostname '{hostname}': {ex}")
            if settings.DEBUG:
                gvars.log.debug(traceback.format_exc())
            return None

    if ip6 is not None:  # "is not None" check makes mypy happier
        if not socket.has_ipv6:
            # TODO: raise exception instead of returning None?
            gvars.log.error(
                "Cannot get the MAC address of a IPv6 host: "
                "IPv6 is not supported on this system"
            )
            return None

        # NOTE: IPv6Interface check must be done first,
        # since it's a sub-class of IPv6Address.
        if isinstance(ip6, IPv6Interface):
            ip6 = str(ip6.ip)
        elif isinstance(ip6, IPv6Address):
            ip6 = str(ip6)
        elif isinstance(ip6, IPv6Network):
            raise ValueError(
                "IPv6Network objects are not supported. getmac needs a host address, "
                "not a network. Try IPv6Address or IPv6Interface instead."
            )
        elif not isinstance(ip6, str):
            raise ValueError(
                f"Unknown type for 'ip6' argument: '{ip6.__class__.__name__}'"
            )

        if ":" not in ip6:
            gvars.log.error(f"Invalid IPv6 address (no ':'): {ip6}")
            return None

    mac = None

    if network_request and (ip or ip6):
        send_udp_packet = True

        # If IPv4, use ArpingHost or CtypesHost if they're available instead
        # of populating the ARP table. This provides more reliable results
        # and a ARP packet is lower impact than a UDP packet.
        if ip:
            if not METHOD_CACHE["ip4"]:
                initialize_method_cache("ip4", network_request)

            # If ArpFile succeeds, just use that, since it's
            # significantly faster than arping (file read vs.
            # spawning a process).
            if not settings.FORCE_METHOD or settings.FORCE_METHOD.lower() == "arpfile":
                af_meth = get_instance_from_cache("ip4", "ArpFile")
                if af_meth:
                    mac = _attempt_method_get(af_meth, "ip4", ip)

            # TODO: add tests for this logic (arpfile => fallback)
            # This seems to be a common course of GitHub issues,
            # so fixing it for good and adding robust tests is
            # probably a good idea.

            if not mac:
                for arp_meth in ["CtypesHost", "ArpingHost"]:
                    if (
                        settings.FORCE_METHOD
                        and settings.FORCE_METHOD.lower() != arp_meth
                    ):
                        continue

                    if arp_meth == str(METHOD_CACHE["ip4"]):
                        send_udp_packet = False
                        break

                    if any(
                        arp_meth == str(x) for x in FALLBACK_CACHE["ip4"]
                    ) and _swap_method_fallback("ip4", arp_meth):
                        send_udp_packet = False
                        break

        # Populate the ARP table by sending an empty UDP packet to a high port
        if send_udp_packet and not mac:
            if settings.DEBUG:
                gvars.log.debug(
                    f"Attempting to populate ARP table with UDP packet "
                    f"to {ip if ip else ip6}:{settings.PORT}"
                )

            if ip:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

            try:
                if ip:
                    sock.sendto(b"", (ip, settings.PORT))
                else:
                    sock.sendto(b"", (ip6, settings.PORT))
            except Exception:
                gvars.log.error("Failed to send ARP table population packet")
                if settings.DEBUG:
                    gvars.log.debug(traceback.format_exc())
            finally:
                sock.close()
        elif settings.DEBUG:
            gvars.log.debug(
                f"Not sending UDP packet, using network request "
                f"method '{METHOD_CACHE['ip4']!s}' instead"
            )

    # Setup the address hunt based on the arguments specified
    if not mac:
        if ip6:
            mac = get_by_method("ip6", ip6)
        elif ip:
            mac = get_by_method("ip4", ip)
        elif interface:
            mac = get_by_method("iface", interface)
        else:  # Default to searching for interface
            # Default to finding MAC of the interface with the default route
            if consts.WINDOWS and network_request:
                default_iface_ip = utils.fetch_ip_using_dns()
                mac = get_by_method("ip4", default_iface_ip)
            elif consts.WINDOWS:
                # TODO: implement proper default interface detection on windows
                #   (add a Method subclass to implement DefaultIface on Windows)
                mac = get_by_method("iface", "Ethernet")
            else:
                if not gvars.DEFAULT_IFACE:
                    gvars.DEFAULT_IFACE = get_by_method("default_iface")  # type: ignore

                    if gvars.DEFAULT_IFACE:
                        gvars.DEFAULT_IFACE = str(gvars.DEFAULT_IFACE).strip()

                    # TODO: better fallback if default iface lookup fails
                    if not gvars.DEFAULT_IFACE and consts.BSD:
                        gvars.DEFAULT_IFACE = "em0"
                    elif not gvars.DEFAULT_IFACE and consts.DARWIN:  # OSX, maybe?
                        gvars.DEFAULT_IFACE = "en0"
                    elif not gvars.DEFAULT_IFACE:
                        gvars.DEFAULT_IFACE = "eth0"

                mac = get_by_method("iface", gvars.DEFAULT_IFACE)

                # TODO: hack to fallback to loopback if lookup fails
                if not mac:
                    mac = get_by_method("iface", "lo")

    gvars.log.debug(f"Raw MAC found: {mac}")

    # Log how long it took
    if settings.DEBUG:
        duration = timeit.default_timer() - start_time
        gvars.log.debug(f"getmac took {duration:0.4f} seconds")

    return utils.clean_mac(mac)
