#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""
Cross-platform Pure-Python 2/3 cross-compatible tool to get a damn MAC address.

It enables you to get the MAC addresses of:
    A local network interface
    A remote host (using IPv4, IPv6, or DNS hostname)
    Your neighbor
    Your dog
    Your mother

It provides one function: get_mac_address()

For the time being, it assumes you are using Ethernet.

Sources:
    Majority of the methods used to attempt, the core logic (notably "getters"),
    and a few others things are attributed to the CPython project and it's UUID code.
    Source 1:
        https://github.com/python/cpython/blob/master/Lib/uuid.py
    Source 2 (Python 2.7 implementation):
        https://github.com/python/cpython/blob/2.7/Lib/uuid.py
"""

# Feature TODO
#   interface
#   ip
#   ip6
#   hostname -> IPv4
#   hostname -> IPv6
#   make_arp_request
#   docstrings
#   comments
#   slim down
#   speed up (spend a lot of time on performance tuning with the regexes)
#   remove print statements OR log errors to stderr OR use logging
#   Test against non-ethernet interfaces (WiFi, LTE, etc.)
#   Threading (spin out all attempts, plus make itself thread-friendly)


# Platform TODO
#   Linux
#   Windows
#   Darwin (Mac OS)
#   OpenBSD
#   FreeBSD
#   Android

# Project TODO
#   Setup Travis (notably with Darwin instances as well)
#   Setup PyPI
#   Badges in readme :P
#   Documentation
#   Examples of usage in README
#   Sick ASCII Cinema capture of usage? (for lulz)
#   Emoji
#   memes
#   ???
#   profit


from __future__ import print_function
import ctypes
import os
import sys
import struct
import socket
import re
import shlex

from subprocess import check_output
try:
    from subprocess import DEVNULL  # Python 3
except ImportError:
    DEVNULL = open(os.devnull, 'wb')  # Python 2


def get_mac_address(interface=None, ip=None, ip6=None, hostname=None, arp_request=False):
    """
    Gets a Unicast IEEE 802 MAC-48 address from a local interface or remote host.

    You must only use one of the first four arguments. If none of the arguments are selected,
    the default network interface for the system will be assumed.

    For remote hosts, it is assumed you have already communicated with the host
    (thus populating the ARP table), and that they reside on your local network.

    Exceptions will be handled silently and returned as a None.
    If you run into problems, create an issue on GitHub, or set DEBUG to true if you're brave.

    :param str interface: Name of a local network interface (e.g "Ethernet 3", "eth0", "ens32")
    :param str ip: Canonical dotted decimal IPv4 address of a remote host (e.g 192.168.0.1)
    :param str ip6: Canononical shortened IPv6 address of a remote host (e.g ff02::1:ffe7:7f19)
    :param str hostname: DNS hostname of a remote host (e.g "router1.mycorp.com")
    :param bool arp_request: Whether to make a ARP/NDP request to the remote host
    to populate the ARP/NDP tables for IPv4/IPv6, respectfully
    :return: Lowercase colon-seperated MAC address,
    or None if one could not be found or there was an error
    :rtype: str or None
    """
    mac = None

    # Get the MAC address of a remote host by hostname
    if hostname is not None:
        print("Hostname: %s" % hostname)
        ip = socket.gethostbyname(hostname)
        # TODO: use getaddrinfo to support ipv6

    # Get MAC of a IPv4 remote host (or a resolved hostname)
    if ip is not None:
        print("IPv4 address: %s" % ip)

    # Get MAC of a IPv6 remote host
    # TODO: "netsh int ipv6 show neigh" (windows cmd)
    elif ip6 is not None:
        if not socket.has_ipv6:
            raise Exception("Cannot get the MAC address of a IPv6 host: "
                            "IPv6 is not supported on this system")
        print("IPv6 address: %s" % ip6)

    # Get MAC of a local interface
    else:
        if interface is not None:
            iface = str(interface)
        else:
            iface = 'default'  # TODO

        # TODO: use IP of interface for functions that require an IP

        if sys.platform == 'win32':
            # _windll_getnode,
            iface_getters = [_windows_netbios, _windows_ipconfig_by_interface]
        else:
            # _unix_getnode, _linux_arp_by_ip, lanscan_getnode
            iface_getters = [_linux_ifconfig_by_interface, _linux_ip_by_interface,
                             _linux_netstat_by_interface, _linux_fcntl_by_interface]

        import traceback
        for getter in iface_getters:
            try:
                _node = getter(iface)
            except Exception as ex:
                print("Exception: %s" % str(ex))
                traceback.print_exc()
                continue
            if _node is not None:
                mac = _node
                break

    if mac is not None:
        return str(mac).lower()
    else:
        return mac


# ***************************
# *-#-*     Windows     *-#-*
# ***************************


# Source: https://code.activestate.com/recipes/347812-get-the-mac-address-of-a-remote-computer/
def _win_get_remote_mac(host):
    """ Returns the MAC address of a network host, requires >= WIN2K. """

    # Check for api availability
    try:
        SendARP = ctypes.windll.Iphlpapi.SendARP
    except:
        raise NotImplementedError('Usage only on Windows 2000 and above')

    # Doesn't work with loopbacks, but let's try and help.
    if host == '127.0.0.1' or host.lower() == 'localhost':
        host = socket.gethostname()

    # gethostbyname blocks, so use it wisely.
    try:
        inetaddr = ctypes.windll.wsock32.inet_addr(host)
        if inetaddr in (0, -1):
            raise Exception
    except:
        hostip = socket.gethostbyname(host)
        inetaddr = ctypes.windll.wsock32.inet_addr(hostip)

    buffer = ctypes.c_buffer(6)
    addlen = ctypes.c_ulong(ctypes.sizeof(buffer))
    if SendARP(inetaddr, 0, ctypes.byref(buffer), ctypes.byref(addlen)) != 0:
        raise WindowsError('Retreival of mac address(%s) - failed' % host)

    # Convert binary data into a string.
    macaddr = ''
    for intval in struct.unpack('BBBBBB', buffer):
        if intval > 15:
            replacestr = '0x'
        else:
            replacestr = 'x'
        macaddr = ''.join([macaddr, hex(intval).replace(replacestr, '')])
    return macaddr


def _windll_getnode():
    """Get the hardware address on Windows using ctypes."""
    pass
    # _load_system_functions()
    # _buffer = ctypes.create_string_buffer(16)
    # if _UuidCreate(_buffer) == 0:
    #     print("WinDLL Buffer: ", _buffer.raw)
    #     # return UUID(bytes=bytes_(_buffer.raw)).node


def _windows_ipconfig_by_interface(interface):
    """Get the hardware address on Windows by running ipconfig.exe."""
    output = _popen('ipconfig', '/all')
    exp = re.escape(interface) + \
        r'(?:\n?[^\n]*){1,8}Physical Address.+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})'
    match = re.search(exp, output)
    if match:
        mac = match.groups()[0]
        # print("Found interface %s in ipconfig. mac: %s" % (interface, mac))
        return mac
        # print("Did not find interface %s in ifconfig." % interface)
    else:
        return None
    # for line in pipe:
    #     value = line.split(':')[-1].strip().lower()
    #     if re.match('([0-9a-f][0-9a-f]-){5}[0-9a-f][0-9a-f]', value):
    #         return value.replace('-', '')


# TODO: extend to specific interface
def _windows_netbios():
    """Get the hardware address on Windows using NetBIOS calls.
    See http://support.microsoft.com/kb/118623 for details.

    Requires: pywin32 (pip install pypiwin32)
    """
    import win32wnet
    import netbios
    ncb = netbios.NCB()
    ncb.Command = netbios.NCBENUM
    ncb.Buffer = adapters = netbios.LANA_ENUM()
    adapters._pack()
    if win32wnet.Netbios(ncb) != 0:
        return
    adapters._unpack()
    for i in range(adapters.length):
        ncb.Reset()
        ncb.Command = netbios.NCBRESET
        ncb.Lana_num = ord(adapters.lana[i])
        if win32wnet.Netbios(ncb) != 0:
            continue
        ncb.Reset()
        ncb.Command = netbios.NCBASTAT
        ncb.Lana_num = ord(adapters.lana[i])
        ncb.Callname = '*'.ljust(16)
        ncb.Buffer = status = netbios.ADAPTER_STATUS()
        if win32wnet.Netbios(ncb) != 0:
            continue
        status._unpack()
        raw_bytes = status.adapter_address[:6]
        if len(raw_bytes) != 6:
            continue
        return int.from_bytes(raw_bytes, 'big')
    print("Failed netbios")


# ******************************
# *-#-*     Unix/Linux     *-#-*
# ******************************


# Get MAC of a specific local interface on Linux
# Source: https://stackoverflow.com/a/4789267/2214380
def _linux_fcntl_by_interface(interface):
    import fcntl
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # TODO: ip6?
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', interface[:15]))
    return ':'.join(['%02x' % ord(char) for char in info[18:24]])


def _unix_getnode():
    """Get the hardware address on Unix using the _uuid extension module
    or ctypes."""
    pass
    # _load_system_functions()
    # uuid_time, _ = _generate_time_safe()
    # print("unix_getnode: ", uuid_time)
    # return UUID(bytes=uuid_time).node


def _linux_ifconfig_by_interface(interface):
    """Get the hardware address on Unix by running ifconfig."""
    # This works on Linux ('' or '-a'), Tru64 ('-av'), but not all Unixes.
    for args in ('', '-a', '-v'):
        match = re.search(
            re.escape(interface) + r'.*(HWaddr|Ether) ([0-9a-f]{2}(?::[0-9a-f]{2}){5})',
            _popen('ifconfig', args))
        if match:
            mac = match.groups()[1]  # Note the 1
            return mac
        else:
            continue
    return None


def _linux_ip_by_interface(interface):
    """Get the hardware address on Unix by running "ip link list"."""
    # This works on Linux with iproute2.
    match = re.search(
        re.escape(interface) + r'.*\n.*link/ether ([0-9a-f]{2}(?::[0-9a-f]{2}){5})',
        _popen('ip', 'link list'))
    if match:
        mac = match.groups()[0]
        return mac
    else:
        return None


# TODO: helper function for "match search if match etc" redundancy


def _linux_arp_by_ip(ip):
    """Get the hardware address on Unix by running arp."""
    match = re.search(
        r'\(' + re.escape(ip) + r'\)\s+at\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})',
        _popen('arp', '-an'))
    if match:
        mac = match.groups()[0]
        return mac
    else:
        return None


# TODO: extend to specific interface
def _linux_lanscan():
    """Get the hardware address on Unix by running lanscan."""
    # This might work on HP-UX.
    return _find_mac('lanscan', '-ai', [b'lan0'], lambda i: 0)


def _linux_netstat_by_interface(interface):
    """Get the hardware address on Unix by running netstat."""
    # This might work on AIX, Tru64 UNIX.
    match = re.search(
        re.escape(interface) + r'.*(HWaddr) ([0-9a-f]{2}(?::[0-9a-f]{2}){5})',
        _popen('netstat', '-iae'))
    if match:
        mac = match.groups()[1]
        return mac
    else:
        return None


# ***********************************
# *-#-*     Utilities/Other     *-#-*
# ***********************************


def _popen(command, args):
    """

    :param str command:
    :param str args:
    :return:
    """
    path = os.environ.get("PATH", os.defpath).split(os.pathsep)
    if sys.platform != 'win32':
        path.extend(('/sbin', '/usr/sbin'))
    for directory in path:
        print("Trying: %s" % str(directory))
        executable = os.path.join(directory, command)
        if (os.path.exists(executable) and
                os.access(executable, os.F_OK | os.X_OK) and
                not os.path.isdir(executable)):
            break
    else:
        print("failed!")
        executable = command
    # LC_ALL=C to ensure English output, stderr=DEVNULL to prevent output
    # on stderr (Note: we don't have an example where the words we search
    # for are actually localized, but in theory some system could do so.)
    env = dict(os.environ)
    env['LC_ALL'] = 'C'
    cmd = [executable] + shlex.split(args)
    proc = check_output(cmd, stderr=DEVNULL)
    # proc = Popen(cmd, stdout=PIPE, stderr=DEVNULL, env=env)
    return proc


def _find_mac(command, args, hw_identifiers, get_index):
    try:
        proc = _popen(command, args)
        for line in proc:
            words = str(line).lower().rstrip().split()
            for i in range(len(words)):
                if words[i] in hw_identifiers:
                    try:
                        word = words[get_index(i)]
                        mac = int(word.replace(':', ''), 16)  # b':', b''
                        if mac:
                            return mac
                    except (ValueError, IndexError):
                        # Virtual interfaces, such as those provided by
                        # VPNs, do not have a colon-delimited MAC address
                        # as expected, but a 16-byte HWAddr separated by
                        # dashes. These should be ignored in favor of a
                        # real MAC address
                        print("found a virtual interface address")
    except OSError:
        print("OSError in find_mac")


if __name__ == "__main__":
    # print(get_mac_address(interface="eth1"))

    if sys.platform == 'win32':
        # _windll_getnode, _windows_netbios
        getters = [_windows_ipconfig_by_interface]
        test_interface = "Ethernet 3"
    else:
        # _unix_getnode, _linux_arp_by_ip, lanscan_getnode
        getters = [_linux_ifconfig_by_interface, _linux_ip_by_interface,
                         _linux_netstat_by_interface, _linux_fcntl_by_interface]
        test_interface = "eth1"

    for getter in getters:
        print("Interface Getter: %s" % getter.__name__)
        print("MAC: %s\n" % getter(test_interface))

    if sys.platform == 'win32':
        getters = [_win_get_remote_mac]
    else:
        getters = [_linux_arp_by_ip]

    test_ip = "10.0.0.1"

    for getter in getters:
        print("IP Getter: %s" % getter.__name__)
        print("MAC: %s\n" % getter(test_ip))
