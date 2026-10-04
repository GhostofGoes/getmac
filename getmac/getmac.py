"""
Get the MAC address of remote hosts or network interfaces.

It provides a platform-independent interface to get the MAC addresses of:

- System network interfaces (by interface name)
- Remote hosts on the local network (by IPv4/IPv6 address or hostname)

The key function is :func:`~getmac.getmac.get_mac_address`.

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

# https://web.archive.org/web/20140718071917/http://multivax.com/last_question.html

import csv
import ctypes
import os
import re
import socket
import struct
import time
import traceback
import warnings
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
    ip_address,
)
from subprocess import CalledProcessError
from typing import Final, Optional, Union

from . import utils
from .variables import consts, gvars, settings

#: Current version of getmac package
__version__ = "1.0.0a0"


class Method:
    """
    Base class defining a method to get a MAC address.
    Subclasses should implement the :meth:`test` and :meth:`get` methods.
    """

    VALID_PLATFORM_NAMES: Final[set[str]] = {
        "android",
        "darwin",
        "linux",
        "windows",
        "wsl",
        "openbsd",
        "freebsd",
        "sunos",
        "hp-ux",
        "other",
    }
    """
    The valid platform identifier strings, used to match
    methods to the appropriate platform.
    """

    platforms: set[str] = set()
    """
    Platforms supported by a method.
    """

    method_type: str = ""
    """
    The type of method, e.g. does it get the MAC of a interface.

    Allowed values:

    - ip
    - ip4
    - ip6
    - iface
    - default_iface
    """

    network_request: bool = False
    """
    If the method makes a network request as part of the check.
    """

    unusable: bool = False
    """
    Marks the method as unable to be used, e.g. if there was a runtime
    error indicating the method won't work on the current platform.
    """

    def test(self) -> bool:
        """
        Low-impact test that the method is feasible, e.g. a command exists.
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
                or interface name. In the case of ``default_iface`` methods,
                this is not used and defaults to an empty string.

        Returns:
            Lowercase colon-separated MAC address, or :obj:`None` if one could
            not be found.
        """
        return None  # pragma: no cover

    @classmethod
    def __str__(cls) -> str:
        return cls.__name__


class ArpFile(Method):
    """
    Use the contents of ``/proc/net/arp`` to find the MAC address of a host.

    Only complete entries are used. Incomplete, failed and proxy ARP entries are
    ignored, since the kernel keeps the last known (possibly stale) MAC for failed
    entries, and proxy ARP entries don't have a real MAC.
    """

    platforms = {"linux"}
    method_type = "ip4"

    _path: Final[str] = os.environ.get("ARP_PATH", "/proc/net/arp")

    # ATF_COM, "completed entry (ha valid)", from include/uapi/linux/if_arp.h.
    # The kernel sets it for entries with a usable MAC (0x2), along with ATF_PERM
    # for permanent entries (0x6). Incomplete and failed entries are 0x0, and
    # proxy ARP entries are 0xc (ATF_PUBL | ATF_PERM) with an all-zero MAC.
    # The net-tools and BusyBox "arp" commands use this flag the same way.
    _ATF_COM: Final[int] = 0x02

    def test(self) -> bool:
        return utils.check_path(self._path)

    def get(self, arg: str) -> Optional[str]:
        if not arg:
            return None

        data = utils.read_file(self._path)

        if data is None:
            self.unusable = True
            return None

        # Columns: IP address, HW type, Flags, HW address, Mask, Device
        # The IP must be the whole first column, otherwise a search for 192.168.16.2
        # would match 192.168.16.254 (or 92.168.16.2 match 192.168.16.2) if it comes first!
        regex = (
            r"^"
            + re.escape(arg)
            + r"[ \t]+\S+[ \t]+(0x[0-9a-fA-F]+)[ \t]+"
            + consts.MAC_RE_COLON
            + r"\s"
        )

        # An IP can have entries on more than one interface, use the first complete one
        for match in re.finditer(regex, data, re.MULTILINE):
            flags, mac = match.groups()
            if int(flags, 16) & self._ATF_COM:
                return mac
            if settings.DEBUG:
                gvars.log.debug(
                    f"ArpFile: ignoring entry without a valid MAC for {arg} (flags: {flags})"
                )

        return None


class ArpFreebsd(Method):
    """
    Use the ``arp`` command to find the MAC address of a host on FreeBSD.
    """

    platforms = {"freebsd"}
    method_type = "ip"

    def test(self) -> bool:
        return utils.check_command("arp")

    def get(self, arg: str) -> Optional[str]:
        regex = r"\(" + re.escape(arg) + r"\)\s+at\s+" + consts.MAC_RE_COLON
        return utils.search(regex, utils.popen("arp", arg=arg))


class ArpOpenbsd(Method):
    """
    Use the ``arp`` command to find the MAC address of a host on OpenBSD.
    """

    platforms = {"openbsd"}
    method_type = "ip"

    _regex: Final[str] = r"[ ]+" + consts.MAC_RE_COLON

    def test(self) -> bool:
        return utils.check_command("arp")

    def get(self, arg: str) -> Optional[str]:
        return utils.search(re.escape(arg) + self._regex, utils.popen("arp", "-an"))


class ArpVariousArgs(Method):
    """
    Use the ``arp`` command to find the MAC address of a host on various platforms.
    """

    platforms = {"linux", "darwin", "freebsd", "sunos", "other"}
    method_type = "ip"

    _regex_std: Final[str] = r"\)\s+at\s+" + consts.MAC_RE_COLON
    _regex_darwin: Final[str] = r"\)\s+at\s+" + consts.MAC_RE_SHORT
    _regex_table: Final[str] = r"[ \t]+\S+[ \t]+" + consts.MAC_RE_COLON + r"\s"

    # Possible arp arguments to try
    # Second element indicates whether to include IP as argument
    _args = (
        ("", True),  # "arp 192.168.1.1"
        # Linux
        # NOTE: "arp -an" was also used by uuid._arp_getnode() in CPython
        ("-an", False),  # "arp -an"
        ("-an", True),  # "arp -an 192.168.1.1"
        # Darwin, WSL, Linux distros???
        ("-a", False),  # "arp -a"
        ("-a", True),  # "arp -a 192.168.1.1"
    )

    # If arguments have been tested
    _args_tested: bool = False
    # arguments that worked
    _good_pair: Union[tuple, tuple[str, bool]] = ()

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
                    # pair_to_test[1]: if True, include the IP as a command argument.
                    # The IP is passed as the untrusted "arg", so it's a single argument.
                    ip_arg = arg if pair_to_test[1] else None
                    command_output = utils.popen("arp", pair_to_test[0], arg=ip_arg)
                    self._good_pair = pair_to_test
                    break
                except CalledProcessError as ex:
                    if settings.DEBUG:
                        gvars.log.debug(
                            f"ArpVariousArgs pair test failed for "
                            f"({pair_to_test[0]}, {pair_to_test[1]}): {ex}"
                        )

            # if no valid argument pair was found, mark unusable
            if not self._good_pair:
                self.unusable = True
                return None

            # Mark args as tested to prevent re-testing on subsequent calls
            self._args_tested = True

        # If tests aren't run (e.g. they ran previously), then run the good pair now
        if not command_output:
            ip_arg = arg if self._good_pair[1] else None
            command_output = utils.popen("arp", self._good_pair[0], arg=ip_arg)

        # Do this here for testing reasons
        if consts.DARWIN or consts.SOLARIS:
            regex = r"\(" + re.escape(arg) + self._regex_darwin
        else:
            regex = r"\(" + re.escape(arg) + self._regex_std

        result = utils.search(regex, command_output)
        if result:
            return result

        # The Linux "arp" from net-tools prints a table instead, e.g. for "arp 10.0.2.2":
        #   Address                  HWtype  HWaddress           Flags Mask            Iface
        #   10.0.2.2                 ether   52:54:00:12:35:02   C                     eth0
        # Incomplete entries have "(incomplete)" instead of a MAC, so they don't match.
        return utils.search(
            r"^" + re.escape(arg) + self._regex_table, command_output, flags=re.MULTILINE
        )


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
        return utils.search(consts.MAC_RE_DASH, utils.popen("arp.exe", "-a", arg=arg))


class NetshNeighbors(Method):
    """
    Use ``netsh.exe`` to find the MAC address of a host in the Windows neighbor cache
    (the ARP table for IPv4, and the NDP neighbor cache for IPv6).

    Microsoft Documentation: `netsh <https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh>`__
    """

    platforms = {"windows"}
    method_type = "ip"

    def test(self) -> bool:
        return utils.check_command("netsh.exe")

    def get(self, arg: str) -> Optional[str]:
        version = "ipv6" if ":" in arg else "ipv4"
        command_output = utils.popen("netsh.exe", f"int {version} show neigh")

        # Columns: Internet Address, Physical Address, Type
        mac = utils.search(
            r"^[ \t]*" + re.escape(arg) + r"[ \t]+" + consts.MAC_RE_DASH + r"[ \t]",
            command_output,
            flags=re.MULTILINE | re.IGNORECASE,
        )

        # Unreachable and incomplete entries don't have a MAC
        if mac == "00-00-00-00-00-00":
            return None

        return mac


class ArpingHost(Method):
    """
    Use ``arping`` command to determine the MAC of a host
    on Linux and Darwin (MacOS).

    This method supports three variants of ``arping``:

    - "habets" arping by Thomas Habets
        (`GitHub <https://github.com/ThomasHabets/arping>`__)
        On Debian-based distros, ``apt install arping`` will install
        Habets arping.
    - "iputils" arping, from the
        `iputils-arping package <https://packages.debian.org/sid/iputils-arping>`__
    - "busybox" arping, included with BusyBox (a small executable "distro")
        (`further reading <https://boxmatrix.info/wiki/Property:arping>`__)

    BusyBox's arping quite similar to iputils-arping. The arguments for
    our purposes are the same, and the output is also the same.
    There's even a TODO in BusyBox's arping code referencing iputils arping.
    There are several differences:

    - The return code from bad arguments is 1, not 2 like for iputils-arping
    - The MAC address in output is lowercase (vs. uppercase in iputils-arping)

    This was a pain to obtain samples for busybox on Windows. I recommend
    using WSL and arping'ing the Docker gateway (for WSL2 distros).
    Note, it must be run as root using ``sudo busybox arping``.
    """

    platforms = {"linux", "darwin"}
    method_type = "ip4"
    network_request = True

    _is_iputils: bool = True
    _habets_args: Final[str] = "-r -C 1 -c 1"
    _iputils_args: Final[str] = "-f -c 1"

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
                command_output = utils.popen("arping", self._iputils_args, arg=arg)
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
                    output = ex.output.decode("utf-8", errors="replace").lower()
                else:
                    output = str(ex.output).lower()

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
        command_output = utils.popen("arping", self._habets_args, arg=arg)
        if command_output:
            return command_output.strip()
        else:
            return None


class CtypesHost(Method):
    """
    Uses ``SendARP`` from the Windows ``Iphlpapi`` to get the MAC address
    of a remote IPv4 host.

    .. note::
       This doesn't work with IPv6.

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
            inetaddr = ctypes.windll.wsock32.inet_addr(hostip.encode())  # type: ignore

        buffer = ctypes.c_buffer(6)
        addlen = ctypes.c_ulong(ctypes.sizeof(buffer))

        # https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-sendarp
        send_arp = ctypes.windll.Iphlpapi.SendARP  # type: ignore
        if send_arp(inetaddr, 0, ctypes.byref(buffer), ctypes.byref(addlen)) != 0:
            return None

        # Convert binary data into a string.
        # buffer.raw is the contents as bytes. PyPy 3.11 (8.0+) doesn't accept the
        # ctypes array itself in struct.unpack().
        macaddr = ""
        for intval in struct.unpack("BBBBBB", buffer.raw):
            if intval > 15:
                replacestr = "0x"
            else:
                replacestr = "x"
            macaddr = "".join([macaddr, hex(intval).replace(replacestr, "")])

        return macaddr


class IpNeighborShow(Method):
    """
    Uses the ``ip neighbor show`` command to get the MAC address
    of a remote host.
    """

    platforms = {"linux", "other"}
    method_type = "ip"  # IPv6 and IPv4

    def test(self) -> bool:
        return utils.check_command("ip")

    def get(self, arg: str) -> Optional[str]:
        output = utils.popen("ip", "neighbor show", arg=arg)
        if not output:
            return None

        try:
            # NOTE: the space prevents accidental matching of partial IPs
            return output.partition(arg + " ")[2].partition("lladdr")[2].strip().split()[0]
        except IndexError as ex:
            gvars.log.debug(f"IpNeighborShow failed with exception: {ex}")
            return None


class SysIfaceFile(Method):
    """
    Uses the contents of ``/sys/class/net/<iface>/address``
    to get the MAC address of a interface.
    """

    platforms = {"linux", "wsl"}
    method_type = "iface"

    _path: Final[str] = "/sys/class/net/"

    def test(self) -> bool:
        # Imperfect, but should work well enough
        return utils.check_path(self._path)

    def get(self, arg: str) -> Optional[str]:
        data = utils.read_file(self._path + arg + "/address")

        # NOTE: if "/sys/class/net/" exists, but interface file doesn't,
        # then that means the interface doesn't exist
        # Sometimes this can be empty or a single newline character
        return None if data is not None and len(data) < 17 else data


class LanscanIface(Method):
    """
    Uses the ``lanscan`` command to get the MAC address of a network interface on HP-UX.

    This is adopted from Python's :mod:`uuid` module's ``_lanscan_getnode`` function.
    """

    platforms = {"hp-ux"}
    method_type = "iface"

    def test(self) -> bool:
        return utils.check_command("lanscan")

    def get(self, arg: str) -> Optional[str]:
        # -a: Display station addresses only. No headings.
        # -i: Display interface names only. No headings.
        output = utils.popen("lanscan", "-ai")
        if not output:
            return None

        # Find the line containing the interface name, e.g. "lan0"
        search_for = arg + " "  # space to prevent partial matches
        for line in output.splitlines():
            if search_for in line:
                # Extract MAC address from the line
                # The raw MAC will be something like "0x0012317D6209"
                # Turn that into a 12-character string, then add colons
                raw_mac = line.split()[0].replace("0x", "").strip()
                return ":".join(raw_mac[i : i + 2] for i in range(0, len(raw_mac), 2))

        return None


class FcntlIface(Method):
    """
    Uses :func:`fcntl.ioctl` to get the MAC address of a network
    interface on Linux (including WSL).
    """

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

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # 0x8927 = SIOCGIFHWADDR, get the hardware (MAC) address
            info = fcntl.ioctl(  # type: ignore
                s.fileno(), 0x8927, struct.pack("256s", encoded_arg[:15])
            )

        return ":".join(["%02x" % ord(chr(char)) for char in info[18:24]])


class GetmacExe(Method):
    """
    Uses Windows-builtin ``getmac.exe`` to get a interface's MAC address.

    The interface can be the connection name (e.g. ``Ethernet 2``) or the network
    adapter (e.g. ``Intel(R) Ethernet Connection I217-V``). Case is ignored, like on Windows.

    Microsoft Documentation: `getmac <https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/getmac>`__
    """

    platforms = {"windows"}
    method_type = "iface"

    def test(self) -> bool:
        # NOTE: the scripts from this library (getmac) are excluded from the
        # path used for checking variables, in getmac.getmac.PATH (defined
        # at the top of this file). Otherwise, this would get messy quickly :)
        return utils.check_command("getmac.exe")

    def get(self, arg: str) -> Optional[str]:
        try:
            # /NH: Suppresses table headers
            # /V:  Verbose, adds the connection name and network adapter
            # /FO CSV: The table format cuts names off at 15 characters  # codespell:ignore fo
            command_output = utils.popen("getmac.exe", "/NH /V /FO CSV")  # codespell:ignore fo
        except CalledProcessError as ex:
            # This shouldn't cause an exception if it's valid command
            gvars.log.error(f"getmac.exe failed, marking unusable. Exception: {ex}")
            self.unusable = True
            return None

        # Columns: Connection Name, Network Adapter, Physical Address, Transport Name
        rows = [row for row in csv.reader(command_output.splitlines()) if len(row) >= 3]
        name = arg.casefold()

        # Connection names first, since a connection could be named after another adapter
        for column in (0, 1):
            for row in rows:
                if row[column].strip().casefold() == name:
                    # Adapters without a MAC have e.g. "N/A" or "Disabled" instead
                    return utils.search(consts.MAC_RE_DASH, row[2])

        return None


class IpconfigExe(Method):
    """
    Uses ``ipconfig.exe`` to find interface MAC addresses on Windows.

    This is generally pretty reliable and works across a wide array of
    versions and releases. I'm not sure if it works pre-XP though.

    The interface can be the adapter name (e.g. ``Ethernet 3``) or its description
    (e.g. ``Intel(R) Ethernet Connection I217-V``). Case is ignored, like on Windows.

    .. note::
       Adapter names are only found in English output, since the headers are
       translated (e.g. "Ethernet adapter Ethernet 3:" is "Carte Ethernet Ethernet 3 :"
       in French). Descriptions are found if the label is "Description".
       The MAC is found in any language.

    Microsoft Documentation: `ipconfig <https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ipconfig>`__
    """

    platforms = {"windows"}
    method_type = "iface"

    # The "Physical Address" label is translated, so match the value instead. It's the
    # only value that's exactly 6 bytes: the DHCPv6 client DUID is longer, and the 8-byte
    # addresses of tunnel adapters aren't MACs.
    _mac_regex: Final[str] = r"^[^:\r\n]*:[ \t]*" + consts.MAC_RE_DASH + r"[ \t\r]*$"
    _description_regex: Final[str] = r"^\s*Description[ .]*:[ \t]*(.*?)[ \t\r]*$"

    def test(self) -> bool:
        return utils.check_command("ipconfig.exe")

    def get(self, arg: str) -> Optional[str]:
        command_output = utils.popen("ipconfig.exe", "/all")
        name = arg.casefold()

        # Each adapter's section starts with a line that isn't indented, e.g.
        # "Ethernet adapter Ethernet 3:", followed by its indented details
        sections = [
            (header.strip().rstrip(":").rstrip(), details)
            for header, _, details in (
                section.partition("\n") for section in re.split(r"\n(?=\S)", command_output)
            )
        ]

        # Adapter names first, then descriptions
        for header, details in sections:
            if header.casefold().partition(" adapter ")[2] == name:
                return utils.search(self._mac_regex, details, flags=re.MULTILINE)

        for _, details in sections:
            description = utils.search(self._description_regex, details, flags=re.MULTILINE)
            if description and description.casefold() == name:
                return utils.search(self._mac_regex, details, flags=re.MULTILINE)

        return None


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

    It only knows about hardware ports (e.g. ``en0``), not other interfaces such as VPN
    tunnels (``utun0``) or ``awdl0``, even if they have a MAC.

    Man page: `networksetup (8) <https://www.manpagez.com/man/8/networksetup/>`__
    """

    platforms = {"darwin"}
    method_type = "iface"

    def test(self) -> bool:
        return utils.check_command("networksetup")

    def get(self, arg: str) -> Optional[str]:
        try:
            command_output = utils.popen("networksetup", "-getmacaddress", arg=arg)
        except CalledProcessError as ex:
            # Exit code 4 is networksetup's error for an invalid argument (it isn't
            # documented, but see https://github.com/meow-rs/meow-rs/pull/698). Here,
            # that's an interface that isn't a hardware port, like a VPN tunnel ("utun0",
            # see GitHub issue #91). That's not a problem with the method, so it isn't
            # raised, which would mark the method unusable.
            if ex.returncode == 4:
                return None
            raise
        return utils.search(consts.MAC_RE_COLON, command_output)


# A MAC that isn't followed by more octets. Otherwise the start of a longer
# hardware address, like InfiniBand's 20-byte "HWaddr", would match as a MAC.
_IFCONFIG_MAC_END: Final[str] = r"(?!:?[0-9a-fA-F])"

# This only took 15-20 hours of throwing my brain against a wall multiple times
# over the span of 1-2 years to figure out. It works for almost all conceivable
# output from "ifconfig", and probably netstat too. It can probably be made more
# efficient by someone who actually knows how to write regex.
# [: ]\s?(?:flags=|\s)(?:[^\n]|\n(?=\s))*?(?:(?:\w+[: ]\s?flags=)|\s(?:ether|address|HWaddr|hwaddr|lladdr)[ :]?\s?([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})(?!:?[0-9a-fA-F]))  # noqa: E501
IFCONFIG_REGEX: Final[str] = (
    r"[: ]\s?(?:flags=|\s)"
    # Stay within this interface. Its other lines are indented, so a line
    # that isn't is the next interface, and its MAC must not be matched.
    r"(?:[^\n]|\n(?=\s))*?(?:"
    r"(?:\w+[: ]\s?flags=)|"  # Prevent interfaces w/o a MAC from matching
    r"\s(?:ether|address|HWaddr|hwaddr|lladdr)[ :]?\s?"  # Handle various prefixes
    # Match the MAC. Octets can be a single digit, e.g. "0:c:29:c1:70:2a" on Solaris.
    r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})" + _IFCONFIG_MAC_END + r")"
)


def _parse_ifconfig(iface: str, command_output: str) -> Optional[str]:
    if not iface or not command_output:
        return None

    # Sanity check on input e.g. if user does "eth0:" as argument
    iface = iface.strip(":")

    # "(?:^|\s)": prevent an input of "h0" from matching on "eth0"
    search_re = r"(?:^|\s)" + re.escape(iface) + IFCONFIG_REGEX

    return utils.search(search_re, command_output, flags=re.DOTALL)


class IfconfigWithIfaceArg(Method):
    """
    ``ifconfig`` command with the interface name as an argument
    (e.g. ``ifconfig eth0``) to determine MAC address of an interface.
    """

    platforms = {"linux", "wsl", "freebsd", "openbsd", "other"}
    method_type = "iface"

    def test(self) -> bool:
        return utils.check_command("ifconfig")

    def get(self, arg: str) -> Optional[str]:
        try:
            command_output = utils.popen("ifconfig", arg=arg)
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
    """
    Determine interface MAC using ``ifconfig`` command
    on Darwin (MacOS) systems.
    """

    platforms = {"darwin"}
    method_type = "iface"

    _tested_arg: bool = False
    _iface_arg: bool = False

    def test(self) -> bool:
        return utils.check_command("ifconfig")

    def get(self, arg: str) -> Optional[str]:
        # Use "ifconfig <arg>", unless it's known that this version of "ifconfig"
        # doesn't accept an interface argument
        if self._iface_arg or not self._tested_arg:
            try:
                command_output = utils.popen("ifconfig", arg=arg)
            except CalledProcessError:
                # The interface doesn't exist, or the argument isn't accepted
                if self._iface_arg:
                    return None
            else:
                self._tested_arg = True
                self._iface_arg = True
                return _parse_ifconfig(arg, command_output)

        mac = _parse_ifconfig(arg, utils.popen("ifconfig", ""))

        # "ifconfig <arg>" failed, but the interface exists, so the argument isn't accepted.
        # If it doesn't exist, this is checked again on the next lookup.
        if mac and not self._tested_arg:
            self._tested_arg = True
            self._iface_arg = False

        return mac


# TODO: create new methods, IfconfigNoArgs and IfconfigVariousArgs
# TODO: unit tests
class IfconfigOther(Method):
    """
    Wild 'Shot in the Dark' attempt at using ``ifconfig``
    to get interface MAC on unknown platforms.
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
    _good_pair: list[Union[str, tuple[str, str]]] = []

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
                        self._good_pair[1] += consts.MAC_RE_COLON + _IFCONFIG_MAC_END
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
                regex = term + consts.MAC_RE_COLON + _IFCONFIG_MAC_END
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
    """
    Determines interface MAC using the ``netstat`` command.
    """

    platforms = {"linux", "wsl", "other"}
    method_type = "iface"

    def test(self) -> bool:
        return utils.check_command("netstat")

    def get(self, arg: str) -> Optional[str]:
        # NOTE: netstat and ifconfig pull from the same kernel source and
        # therefore have the same output format on the same platform.
        command_output = utils.popen("netstat", "-iae")
        if not command_output:
            gvars.log.warning("no netstat output, marking unusable")
            self.unusable = True
            return None

        return _parse_ifconfig(arg, command_output)


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
    """
    Determines interface MAC using the ``ip link`` command.
    """

    platforms = {"linux", "wsl", "android", "other"}
    method_type = "iface"

    _regex: Final[str] = r".*\n.*link/ether " + consts.MAC_RE_COLON
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
                command_output = utils.popen("ip", "link show", arg=arg)
                self._iface_arg = True
            except CalledProcessError as err:
                # Output: 'Command "eth0" is unknown, try "ip link help"'
                if err.returncode != 255:
                    raise err
            self._tested_arg = True

        if self._iface_arg:
            if not command_output:  # Don't repeat work on first run
                command_output = utils.popen("ip", "link show", arg=arg)
            return utils.search(re.escape(arg) + self._regex, command_output)
        else:
            # TODO: improve this regex to not need extra portion for no arg
            # "(?:^|\s)": prevent an input of "h0" from matching on "eth0"
            command_output = utils.popen("ip", "link")
            return utils.search(r"(?:^|\s)" + re.escape(arg) + r":" + self._regex, command_output)


class DefaultIfaceLinuxRouteFile(Method):
    """
    Determine the default interface by parsing the ``/proc/net/route`` file
    on Linux-based platforms (including WSL).

    This is the same source as the ``route`` command, however it's much
    faster to read this file than to call ``route``. If it fails for whatever
    reason, we can fall back on the system commands (e.g for a platform that
    has a route command, but doesn't use ``/proc``, such as BSD-based platforms).
    """

    platforms = {"linux", "wsl"}
    method_type = "default_iface"

    _path: Final[str] = "/proc/net/route"

    def test(self) -> bool:
        return utils.check_path(self._path)

    def get(self, arg: str = "") -> Optional[str]:  # noqa: ARG002
        data = utils.read_file(self._path)

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
                    f"'{self._path}', no destination of '00000000' was found"
                )
        elif settings.DEBUG:
            gvars.log.warning(f"No data from {self._path}")

        return None


class DefaultIfaceRouteCommand(Method):
    """
    Determine default interface using the ``route -n`` command.
    """

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
        except IndexError as ex:
            # index errors means no default route in output?
            gvars.log.debug(f"DefaultIfaceRouteCommand failed for {arg}: {ex}")
            return None


class DefaultIfaceRouteGetCommand(Method):
    """
    Determine default interface using the ``route get default`` command
    on BSD-based platforms, including Darwin (MacOS).
    """

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
    """
    Determine the default interface using the ``ip route`` command.
    """

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

        # Use the interface name after "dev". The fields after it vary, e.g.
        # "proto dhcp ...", "onlink" or nothing at all, so don't rely on them.
        return utils.search(r"\bdev\s+(\S+)", output)


class DefaultIfaceOpenBsd(Method):
    """
    Determine the default interface on OpenBSD using the ``route`` command.

    The full command is ``route -nq show -inet -gateway -priority 1``.
    """

    platforms = {"openbsd"}
    method_type = "default_iface"

    def test(self) -> bool:
        return utils.check_command("route")

    def get(self, arg: str = "") -> Optional[str]:  # noqa: ARG002
        output = utils.popen("route", "-nq show -inet -gateway -priority 1")
        return output.partition("127.0.0.1")[0].strip().rpartition(" ")[2]


class DefaultIfaceFreeBsd(Method):
    """
    Determine the default interface on FreeBSD using the ``netstat`` command.

    The full command is ``netstat -r``.
    """

    platforms = {"freebsd"}
    method_type = "default_iface"

    def test(self) -> bool:
        return utils.check_command("netstat")

    def get(self, arg: str = "") -> Optional[str]:  # noqa: ARG002
        output = utils.popen("netstat", "-r")
        return utils.search(r"default[ ]+\S+[ ]+\S+[ ]+(\S+)[\r\n]+", output)


class DefaultIfaceNetsh(Method):
    """
    Use ``netsh.exe`` to find the default interface on Windows:
    the interface of the IPv4 default route (``0.0.0.0/0``) with the lowest metric.

    Microsoft Documentation: `netsh <https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh>`__
    """

    platforms = {"windows"}
    method_type = "default_iface"

    # Columns: Publish, Type, Met, Prefix, Idx, Gateway/Interface Name
    _regex: Final[str] = (
        r"^[ \t]*\S+[ \t]+\S+[ \t]+(\d+)[ \t]+(\S+)[ \t]+(\d+)[ \t]+(.+?)[ \t\r]*$"
    )

    def test(self) -> bool:
        return utils.check_command("netsh.exe")

    def get(self, arg: str = "") -> Optional[str]:  # noqa: ARG002
        command_output = utils.popen("netsh.exe", "int ipv4 show route")
        routes = re.findall(self._regex, command_output, flags=re.MULTILINE)

        # Default routes, lowest metric first
        default_routes = sorted(
            (route for route in routes if route[1] == "0.0.0.0/0"), key=lambda r: int(r[0])
        )

        # A default route through a gateway shows the gateway's IP instead of the
        # interface name, so the name comes from another route on the same interface
        # (the same "Idx"), such as the route for its subnet.
        for _, _, default_idx, _ in default_routes:
            for _, _, idx, name in routes:
                if idx == default_idx and not _is_ip_address(name):
                    return name

        return None


def _is_ip_address(text: str) -> bool:
    try:
        ip_address(text)
    except ValueError:
        return False
    return True


# TODO: order methods by effectiveness/reliability
#   Use a class attribute maybe? e.g. "score", then sort by score in cache
METHODS: list[type[Method]] = [
    # NOTE: CtypesHost is faster than ArpExe because of sub-process startup times :)
    CtypesHost,
    ArpFile,
    ArpingHost,
    SysIfaceFile,
    FcntlIface,
    LanscanIface,
    GetmacExe,
    IpconfigExe,
    WmicExe,
    ArpExe,
    NetshNeighbors,
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
    DefaultIfaceLinuxRouteFile,
    DefaultIfaceIpRoute,
    DefaultIfaceRouteCommand,
    DefaultIfaceRouteGetCommand,
    DefaultIfaceOpenBsd,
    DefaultIfaceFreeBsd,
    DefaultIfaceNetsh,
]

# TODO: move to gvars class? gotta love import loops with type annotations.
#   Use deferred annotations/string annotations.
METHOD_CACHE: dict[str, Optional[Method]] = {
    "ip4": None,
    "ip6": None,
    "iface": None,
    "default_iface": None,
}
"""
Primary method to use for a given method type
"""


# TODO: move to gvars class?
FALLBACK_CACHE: dict[str, list[Method]] = {
    "ip4": [],
    "ip6": [],
    "iface": [],
    "default_iface": [],
}
"""
Order of methods is determined by:

- Platform + version
- Performance (file read > command)
- Reliability (how well I know/understand the command to work)
"""


def get_method_by_name(method_name: str) -> Optional[type[Method]]:
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

    found: Optional[Method] = None
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

    Raises:
        RuntimeError: if no valid methods were found for the given method type
            and the system's platform (or user-defined override platform), or
            if all matching methods failed to test.
    """
    if METHOD_CACHE.get(method_type):
        if settings.DEBUG:
            gvars.log.debug(f"Method cache already initialized for method type '{method_type}'")
        return True

    gvars.log.debug(f"Initializing '{method_type}' method cache (platform: '{consts.PLATFORM}')")

    # Platform identifiers are lowercase, but allow values like "Darwin" from platform.system()
    override_platform = (settings.OVERRIDE_PLATFORM or "").strip().lower()

    if override_platform:
        gvars.log.warning(
            f"Platform override is set, using '{override_platform}' as platform "
            f"instead of detected platform '{consts.PLATFORM}'"
        )
        platform = override_platform
    else:
        platform = consts.PLATFORM

    if settings.DEBUG >= 4:
        meth_strs = ", ".join(m.__name__ for m in METHODS)
        gvars.log.debug(f"{len(METHODS)} methods available: {meth_strs}")

    # Filter methods by the type of MAC we're looking for, such as "ip"
    # for remote host methods or "iface" for local interface methods.
    type_methods: list[type[Method]] = [
        method
        for method in METHODS
        if (method.method_type != "ip" and method.method_type == method_type)
        # Methods with a type of "ip" can handle both IPv4 and IPv6
        or (method.method_type == "ip" and method_type in ["ip4", "ip6"])
    ]

    if not type_methods:
        raise RuntimeError(f"No valid methods matching MAC type '{method_type}'")

    if settings.DEBUG >= 2:
        type_strs = ", ".join(tm.__name__ for tm in type_methods)
        gvars.log.debug(
            f"{len(type_methods)} type-filtered methods for '{method_type}': {type_strs}"
        )

    # Filter methods by the platform we're running on
    platform_methods: list[type[Method]] = [
        method for method in type_methods if platform in method.platforms
    ]

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
        platform_methods = [method for method in type_methods if "other" in method.platforms]

    if settings.DEBUG >= 2:
        plat_strs = ", ".join(pm.__name__ for pm in platform_methods)
        gvars.log.debug(
            f"{len(platform_methods)} platform-filtered methods for '{platform}' "
            f"(method_type='{method_type}'): {plat_strs}"
        )

    if not platform_methods:
        raise RuntimeError(
            f"No valid methods found for MAC type '{method_type}' and platform '{platform}'"
        )

    filtered_methods: list[type[Method]] = platform_methods

    # If network_request is False, then remove any methods that have network_request=True
    if not network_request:
        filtered_methods = [m for m in platform_methods if not m.network_request]

    # Determine which methods work on the current system
    tested_methods: list[Method] = []

    for method_class in filtered_methods:
        method_instance: Method = method_class()
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
        names = ", ".join(m.__name__ for m in filtered_methods)
        raise RuntimeError(
            f"All {len(filtered_methods)} '{method_type}' methods failed to test! The "
            f"commands or files they use may be missing or not accessible ({names})"
        )

    if settings.DEBUG >= 2:
        tested_strs = ", ".join(str(ts) for ts in tested_methods)
        gvars.log.debug(f"{len(tested_methods)} tested methods for '{method_type}': {tested_strs}")

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
    if method is METHOD_CACHE[method_type]:
        if not FALLBACK_CACHE[method_type]:
            gvars.log.warning(f"No fallback method for unusable method '{method!s}'!")
            METHOD_CACHE[method_type] = None
        else:
            METHOD_CACHE[method_type] = FALLBACK_CACHE[method_type].pop(0)
            gvars.log.warning(
                f"Falling back to '{METHOD_CACHE[method_type]!s}' for unusable method '{method!s}'"
            )
    elif method in FALLBACK_CACHE[method_type]:
        # E.g. ArpFile, which get_mac_address() uses before the cached method
        FALLBACK_CACHE[method_type].remove(method)
        gvars.log.warning(f"Removed unusable fallback method '{method!s}'")

    return METHOD_CACHE[method_type]


def _select_method(method_type: str, network_request: bool = True) -> Optional[Method]:
    """
    The cached method to use: the one in :data:`~getmac.getmac.METHOD_CACHE`, or if it sends
    network requests and ``network_request`` is :obj:`False`, the first one in
    :data:`~getmac.getmac.FALLBACK_CACHE` that doesn't.
    """
    for method in (METHOD_CACHE[method_type], *FALLBACK_CACHE[method_type]):
        if method and (network_request or not method.network_request):
            return method

    return None


def _attempt_method_get(
    method: Method,
    method_type: str,
    arg: str,
    network_request: bool = True,
    fallback: bool = True,
) -> Optional[str]:
    """
    Attempt to use methods, and if they fail, fallback to the next method in the cache.

    Methods that send network requests aren't used as fallbacks if ``network_request``
    is :obj:`False`. If ``fallback`` is :obj:`False`, a method that fails is still removed
    from the caches, but no other method is tried.
    """
    if not METHOD_CACHE[method_type] and not FALLBACK_CACHE[method_type]:
        raise RuntimeError(f"No usable methods found for MAC type '{method_type}'")

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
        _remove_unusable(method, method_type)
        new_method = _select_method(method_type, network_request) if fallback else None

        if not new_method:
            return None

        return _attempt_method_get(new_method, method_type, arg, network_request)

    return result


def get_by_method(method_type: str, arg: str = "", network_request: bool = True) -> Optional[str]:
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
            gvars.log.error(f"Invalid FORCE_METHOD method name '{settings.FORCE_METHOD}'")
            return None

        return forced_method().get(arg)

    # Initialize the cache if it hasn't been already
    if not METHOD_CACHE.get(method_type) and not initialize_method_cache(
        method_type, network_request
    ):
        gvars.log.error(
            f"Failed to initialize method cache for method '{method_type}' (arg: '{arg}')"
        )
        return None

    # The cache can have methods that send network requests,
    # if it was initialized by a lookup that allowed them
    method = _select_method(method_type, network_request)

    if not method:
        gvars.log.error(
            f"No usable methods for '{method_type}' lookups. It may not be supported on this "
            f"platform, or all of its methods send network requests (network_request is False)."
        )
        return None

    result = _attempt_method_get(method, method_type, arg, network_request)

    # Log normal get() failures if debugging is enabled
    if settings.DEBUG and not result:
        gvars.log.debug(f"Method '{method!s}' failed for '{method_type}' lookup")

    return result


def _lookup_host(method_type: str, host: str, network_request: bool, wait: bool) -> Optional[str]:
    """
    Look up a host's MAC. If it isn't found and ``wait`` is :obj:`True` (the UDP packet
    was sent), look it up again until it's found or
    :attr:`~getmac.variables.Settings.ARP_TIMEOUT` seconds have passed, waiting longer each
    time. It takes a moment for the host to reply to the request sent for the UDP packet,
    and for its entry to be added to the table (GitHub issue #101).
    """
    mac = get_by_method(method_type, host, network_request)
    if mac or not wait or settings.ARP_TIMEOUT <= 0:
        return mac

    deadline = time.monotonic() + settings.ARP_TIMEOUT
    delay = 0.01

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            gvars.log.debug(f"Host {host} not found after waiting {settings.ARP_TIMEOUT}s")
            return None

        time.sleep(min(delay, remaining))
        delay *= 2

        mac = get_by_method(method_type, host, network_request)
        if mac:
            return mac


def _default_interface_mac(network_request: bool) -> Optional[str]:
    """
    MAC of the default interface, or if it can't be found or doesn't have a MAC
    (e.g. a VPN tunnel), the first interface that isn't a loopback interface and has one.
    """
    if not gvars.DEFAULT_IFACE:
        default_iface = get_by_method("default_iface", network_request=network_request)
        gvars.DEFAULT_IFACE = default_iface.strip() if default_iface else ""

    if gvars.DEFAULT_IFACE:
        mac = get_by_method("iface", gvars.DEFAULT_IFACE, network_request)
        if mac:
            return mac
        gvars.log.debug(f"Default interface '{gvars.DEFAULT_IFACE}' doesn't have a MAC")
    else:
        # E.g. there aren't any routes (GitHub issue #78)
        gvars.log.debug("Failed to find the default interface")

    # On Windows, if_nameindex() names (e.g. "ethernet_32768") aren't the
    # names the methods use (e.g. "Ethernet"), and loopback has no MAC anyway
    if consts.WINDOWS:
        return None

    try:
        interfaces = [name for _, name in socket.if_nameindex()]
    except (AttributeError, OSError) as ex:
        gvars.log.debug(f"Failed to list the interfaces: {ex}")
        return None

    for iface in interfaces:
        # Loopback is "lo" on Linux, "lo0" on macOS, the BSDs, and Solaris
        if iface == gvars.DEFAULT_IFACE or re.fullmatch(r"lo\d*", iface):
            continue

        mac = get_by_method("iface", iface, network_request)
        if mac and utils.clean_mac(mac) != "00:00:00:00:00:00":
            gvars.log.debug(f"Using the MAC of the first interface with a MAC, '{iface}'")
            return mac

    return None


# Characters that must never appear in an interface name. They could be read as extra
# command-line arguments, or break out of a quoted query (such as WMIC's WQL), when the
# name is passed to a command. Interface names on the supported platforms don't use them.
_INTERFACE_BAD_CHARS: Final[str] = "'\"`\\/"


def _validate_interface(interface: str) -> str:
    """
    Check that an interface name is safe to pass to a command, and return it unchanged.

    This guards against argument injection and command-injection-like behavior when the
    name reaches a command (`GitHub issue #61 <https://github.com/GhostofGoes/getmac/issues/61>`__).

    Raises:
        ValueError: the name is empty, looks like a command-line flag, or has characters
            that aren't valid in an interface name
    """
    if not interface:
        raise ValueError("Interface name cannot be empty")
    if interface.startswith("-"):
        raise ValueError(f"Invalid interface name (cannot start with '-'): {interface!r}")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in interface):
        raise ValueError(f"Invalid interface name (contains control characters): {interface!r}")
    bad = sorted({c for c in interface if c in _INTERFACE_BAD_CHARS})
    if bad:
        raise ValueError(f"Invalid interface name (contains {bad}): {interface!r}")
    # Interface names don't contain whitespace on POSIX. Windows connection names can,
    # e.g. "Local Area Connection".
    if not consts.WINDOWS and any(c.isspace() for c in interface):
        raise ValueError(f"Invalid interface name (contains whitespace): {interface!r}")
    return interface


def _validate_ip4(ip: str) -> str:
    """Parse an IPv4 address and return it in canonical form, or raise ``ValueError``."""
    try:
        return str(IPv4Address(ip))
    except ValueError:
        raise ValueError(f"Invalid IPv4 address: {ip!r}") from None


def _validate_ip6(ip6: str) -> str:
    """
    Parse an IPv6 address and return it in canonical form, or raise ``ValueError``.

    An interface scope ID is kept (e.g. ``fe80::1%eth0``) and validated as an interface
    name, since it's passed through to commands the same way.
    """
    address, separator, scope = ip6.partition("%")
    try:
        canonical = str(IPv6Address(address))
    except ValueError:
        raise ValueError(f"Invalid IPv6 address: {ip6!r}") from None
    if separator:
        _validate_interface(scope)
        return f"{canonical}%{scope}"
    return canonical


def get_mac_address(
    interface: Union[str, bytes, None] = None,
    ip: Union[str, bytes, IPv4Address, IPv4Interface, IPv6Address, IPv6Interface, None] = None,
    ip6: Union[str, bytes, IPv6Address, IPv6Interface, None] = None,
    hostname: Union[str, bytes, None] = None,
    network_request: bool = True,
) -> Optional[str]:
    """
    Get a MAC address from a local interface or remote host.

    Only ONE of the first four arguments may be used:
    ``interface``, ``ip``, ``ip6``, or ``hostname``.
    If none of the arguments are selected, the default network interface for
    the system will be used. If it can't be found or doesn't have a MAC, the first
    interface that has a MAC and isn't a loopback interface is used (except on Windows).

    The MAC is usually a unicast IEEE 802 MAC-48 address.

    .. note::
       ``"localhost"`` or ``"127.0.0.1"`` will always return ``"00:00:00:00:00:00"``

    .. note::
       It is assumed that the host is using Ethernet or Wi-Fi. While other protocols
       such as Bluetooth may work, this has not been tested and should not be
       relied upon. If this functionality is needed, please open an issue or PR.

    .. note::
       Exceptions raised by *methods* are handled silently and returned as :obj:`None`.

    Args:
        interface: Name of a local network interface (e.g "Ethernet 3", "eth0", "ens32")
        ip: Canonical dotted decimal IPv4 address of a remote host (e.g ``192.168.0.1``),
            or a :mod:`ipaddress` object (:class:`~ipaddress.IPv4Address` or
            :class:`~ipaddress.IPv4Interface`). This will also accept
            :class:`~ipaddress.IPv6Address` and :class:`~ipaddress.IPv6Interface`,
            and treat them as if ``ip6`` argument was set instead.
        ip6: Canonical shortened IPv6 address of a remote host (e.g ``ff02::1:ffe7:7f19``),
            or a :mod:`ipaddress` object (:class:`~ipaddress.IPv6Address`
            or :class:`~ipaddress.IPv6Interface`).
        hostname: DNS hostname of a remote host (e.g "router1.mycorp.com", "localhost")
        network_request: If network requests should be made when attempting to find the
            MAC of a remote host. If the ``arping`` command is available, this will be used.
            If not, a UDP packet will be sent to the remote host to populate
            the ARP/NDP tables for IPv4/IPv6. The port this packet is sent to can
            be configured using the setting :attr:`getmac.variables.Settings.PORT`
            (by default, it's port 55555). To wait for the host to reply to it, set
            :attr:`getmac.variables.Settings.ARP_TIMEOUT`. If this is :obj:`False`,
            methods that send network requests (such as ``arping``) aren't used.

    Returns:
        Lowercase colon-separated MAC address. If no MAC was found, or an exception
        occurred, :obj:`None` is returned.

    Raises:
        RuntimeError: If no valid methods are found for the type of MAC requested,
            or another critical error occurs (potentially due to a bug in getmac).
    """

    # If debugging, start the timer
    if settings.DEBUG:
        import timeit

        start_time = timeit.default_timer()

    # Convert bytes to str, assuming UTF-8 encoding
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
            raise ValueError(f"Unknown type for 'ip' argument: '{ip.__class__.__name__}'")

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
                "Cannot get the MAC address of a IPv6 host: IPv6 is not supported on this system"
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
            raise ValueError(f"Unknown type for 'ip6' argument: '{ip6.__class__.__name__}'")

        ip6 = _validate_ip6(ip6)

    if ip is not None:
        ip = _validate_ip4(ip)

    if interface is not None:
        interface = _validate_interface(interface)

    mac = None
    udp_packet_sent = False

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
                    # If it fails, it's removed from the caches, but the
                    # cached method isn't used yet (that's done below)
                    mac = _attempt_method_get(af_meth, "ip4", ip, fallback=False)

            # TODO: add tests for this logic (arpfile => fallback)
            # This seems to be a common course of GitHub issues,
            # so fixing it for good and adding robust tests is
            # probably a good idea.

            if not mac:
                for arp_meth in ["CtypesHost", "ArpingHost"]:
                    if settings.FORCE_METHOD and settings.FORCE_METHOD.lower() != arp_meth.lower():
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
                udp_packet_sent = True
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
            mac = _lookup_host("ip6", ip6, network_request, wait=udp_packet_sent)
        elif ip:
            mac = _lookup_host("ip4", ip, network_request, wait=udp_packet_sent)
        elif interface:
            mac = get_by_method("iface", interface, network_request)
        # === Default to searching for interface ===
        else:
            if consts.WINDOWS and network_request:
                # The IP of the interface with the default route
                try:
                    default_iface_ip = utils.fetch_ip_using_dns()
                except OSError as ex:
                    gvars.log.warning(f"Failed to get the IP of the default interface: {ex}")
                else:
                    mac = get_by_method("ip4", default_iface_ip, network_request)

            if not mac:
                mac = _default_interface_mac(network_request)

    gvars.log.debug(f"Raw MAC found: {mac}")

    # Log how long it took
    if settings.DEBUG:
        duration = timeit.default_timer() - start_time
        gvars.log.debug(f"getmac took {duration:0.4f} seconds")

    return utils.clean_mac(mac)


def get_default_interface() -> Optional[str]:
    """
    Get the name of the default network interface on the system.

    This is essentially a convenience wrapper around
    :func:`get_by_method` with the ``default_iface`` method type.
    The code is literally
    ``return getmac.getmac.get_by_method("default_iface")``.

    Returns:
        The name of the default network interface, or :obj:`None`
        if it could not be found or an exception occurred.
    """
    return get_by_method("default_iface")
