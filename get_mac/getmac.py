#!/usr/bin/env python
# -*- coding: utf-8 -*-

# http://multivax.com/last_question.html

"""
Cross-platform Pure-Python 2/3 tool to get a gosh-darn MAC address.

It enables you to get the MAC addresses of:
    A local network interface
    A remote host (using IPv4, IPv6, or DNS hostname)
    Your neighbor
    Your dog
    Your mother

It provides one function: get_mac_address()

Sources:
    Many of the methods used to accquire an address and the core logic framework
    are attributed to the CPython project's UUID implementation.
        https://github.com/python/cpython/blob/master/Lib/uuid.py
        https://github.com/python/cpython/blob/2.7/Lib/uuid.py
    Other sources are noted with inline comments at the appropriate sections.

Messages are output using the warnings library.
If you are using logging, they can be captured using logging.captureWarnings().
Otherwise, they can be suppressed using warnings.filterwarnings("ignore").
https://docs.python.org/2/library/warnings.html
"""

__version__ = "0.0.4"


import ctypes
import os
import sys
import struct
import socket
import re
import shlex
import warnings
from subprocess import Popen, PIPE, CalledProcessError
try:
    from subprocess import DEVNULL    # Python 3
except ImportError:
    DEVNULL = open(os.devnull, 'wb')  # Python 2

DEBUG = False  # TODO


def get_mac_address(interface=None, ip=None, ip6=None,
                    hostname=None, arp_request=False):
    """
    Get a Unicast IEEE 802 MAC-48 address from a local interface or remote host.

    You must only use one of the first four arguments.
    If none of the arguments are selected,
    the default network interface for the system will be assumed.

    For remote hosts, it is assumed you have already communicated with the host
    (thus populating the ARP table), and that they reside on your local network.

    Exceptions will be handled silently and returned as a None.
    If you run into problems, create an issue on GitHub,
    or set DEBUG to true if you're brave.

    For the time being, it assumes you are using Ethernet.

    :param str interface: Name of a local network interface
    (e.g "Ethernet 3", "eth0", "ens32")
    :param str ip: Canonical dotted decimal IPv4 address of a remote host
    (e.g 192.168.0.1)
    :param str ip6: Canononical shortened IPv6 address of a remote host
    (e.g ff02::1:ffe7:7f19)
    :param str hostname: DNS hostname of a remote host
    (e.g "router1.mycorp.com")
    :param bool arp_request: Make a ARP/NDP request to the remote host
    to populate the ARP/NDP tables for IPv4/IPv6, respectfully
    :return: Lowercase colon-seperated MAC address,
    or None if one could not be found or there was an error
    :rtype: str or None
    """
    mac = None  # MAC address
    funcs = []  # Functions to try using to get a MAC
    arg = None  # Argument to the functions (e.g IP or interface)

    # Get the MAC address of a remote host by hostname
    if hostname is not None:
        ip = socket.gethostbyname(hostname)
        # TODO: IPv6 support: use getaddrinfo instead of gethostbyname
        # This would handle case of an IPv6 host

    # Populate the ARP table using a simple ping
    if arp_request:
        if sys.platform == 'win32':  # Windows
            _popen("ping", "-n 1 %s" % ip if ip is not None else ip6)
        else:  # Non-Windows
            if ip is not None:  # IPv4
                _popen("ping", "-c 1 %s" % ip)
            else:  # IPv6
                _popen("ping6", "-c 1 %s" % ip6)

    # Get MAC of a IPv4 remote host (or a resolved hostname)
    if ip is not None:
        arg = ip
        if sys.platform == 'win32':  # Windows
            funcs = [_windows_get_remote_mac]
        else:  # Non-Windows
            funcs = [_unix_arp_by_ip]

    # Get MAC of a IPv6 remote host
    # TODO: "netsh int ipv6 show neigh" (windows cmd)
    elif ip6 is not None:
        if not socket.has_ipv6:
            warnings.warn("Cannot get the MAC address of a IPv6 host: "
                          "IPv6 is not supported on this system",
                          RuntimeWarning)
            return None
        arg = ip6

    # Get MAC of a local interface
    else:
        if interface is not None:
            arg = str(interface)
        # Determine what interface is "default" (has default route)
        elif sys.platform == 'win32':  # Windows
            # TODO: default route OR first interface found windows
            arg = "Ethernet 1"
        else:  # Non-Windows
            # TODO: default route OR first interface found non-windows
            arg = 'eth0'

        if sys.platform == 'win32':  # Windows
            # _windll_getnode,
            funcs = [_windows_ipconfig_by_interface]
        else:  # Non-Windows
            # _unix_getnode, _unix_arp_by_ip, lanscan_getnode
            funcs = [_unix_ifconfig_by_interface, _unix_ip_by_interface,
                     _unix_netstat_by_interface, _unix_fcntl_by_interface]

    # We try every function and see if it returned a MAC address
    # If it returns None or raises an exception,
    # we continue and try the next function
    for func in funcs:
        try:
            mac = func(arg)
        except Exception as ex:
            if DEBUG:
                print("Exception: %s" % str(ex))  # TODO
                import traceback
                traceback.print_exc()
            continue
        if mac is not None:
            break

    # Make sure address is formatted properly
    if mac is not None:
        # lowercase, colon-separated
        # NOTE: we cast to str ONLY here and NO WHERE ELSE to prevent
        # possibly returning "None" strings.
        mac = str(mac).lower().replace("-", ":")

        # Fix cases where there are no colons
        if len(mac) == 12:
            # Source: https://stackoverflow.com/a/3258612/2214380
            mac = ':'.join(mac[i:i + 2] for i in range(0, len(mac), 2))

        # MAC address should ALWAYS be 17 characters with the colons
        if len(mac) != 17:
            mac = None

    return mac


# ***************************
# *-#-*     Windows     *-#-*
# ***************************

# Source: https://goo.gl/ymhZ9p
def _windows_get_remote_mac(host):
    # requires windows 2000 or newer

    # Check for api availability
    try:
        SendARP = ctypes.windll.Iphlpapi.SendARP
    except Exception:
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

    # TODO: arp_request flag
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
    pass
    # _load_system_functions()
    # _buffer = ctypes.create_string_buffer(16)
    # if _UuidCreate(_buffer) == 0:
    #     # return UUID(bytes=bytes_(_buffer.raw)).node


def _windows_ipconfig_by_interface(interface):
    return _search(re.escape(interface) +
                   r'(?:\n?[^\n]*){1,8}Physical Address.+'
                   r'([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})',
                   _popen('ipconfig', '/all'))


# ******************************
# *-#-*     Unix/Linux     *-#-*
# ******************************

# Source: https://stackoverflow.com/a/4789267/2214380
def _unix_fcntl_by_interface(interface):
    import fcntl
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # TODO: ip6?
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', interface[:15]))
    return ':'.join(['%02x' % ord(char) for char in info[18:24]])


def _unix_getnode():
    pass
    # _load_system_functions()
    # uuid_time, _ = _generate_time_safe()
    # return UUID(bytes=uuid_time).node


def _unix_ifconfig_by_interface(interface):
    # This works on Linux ('' or '-a'), Tru64 ('-av'), but not all Unixes.
    for arg in ('', '-a', '-av', '-v'):
        mac = _search(re.escape(interface) +
                      r'.*(HWaddr|Ether) ([0-9a-f]{2}(?::[0-9a-f]{2}){5})',
                      _popen('ifconfig', arg))
        if mac:
            return mac
        else:
            continue
    return None


def _unix_ip_by_interface(interface):
    return _search(re.escape(interface) +
                   r'.*\n.*link/ether ([0-9a-f]{2}(?::[0-9a-f]{2}){5})',
                   _popen('ip', 'link list'))


def _unix_arp_by_ip(ip):
    try:
        return _search(r'\(' + re.escape(ip) +
                       r'\)\s+at\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})',
                       _popen('arp', '-an'))
    except Exception:
        return _search(re.escape(ip) + r'.*([0-9a-f]{2}(?::[0-9a-f]{2}){5})',
                       _popen('cat', '/proc/net/arp'))


def _hp_ux_lanscan(interface):
    return _find_mac('lanscan', '-ai', [interface], lambda i: 0)


def _unix_netstat_by_interface(interface):
    return _search(re.escape(interface) +
                   r'.*(HWaddr) ([0-9a-f]{2}(?::[0-9a-f]{2}){5})',
                   _popen('netstat', '-iae'), group_index=1)


# ***********************************
# *-#-*     Utilities/Other     *-#-*
# ***********************************

def _search(regex, text, group_index=0):
    match = re.search(regex, text)
    if match:
        return match.groups()[group_index]
    else:
        return None


def _popen(command, args):
    # Try to find the full path to the actual executable of the command
    # This prevents snafus from shell weirdness and other things
    path = os.environ.get("PATH", os.defpath).split(os.pathsep)
    if sys.platform != 'win32':
        path.extend(('/sbin', '/usr/sbin'))  # Add sbin to path on Unix
    for directory in path:
        executable = os.path.join(directory, command)
        if (os.path.exists(executable) and
                os.access(executable, os.F_OK | os.X_OK) and
                not os.path.isdir(executable)):
            break
    else:
        executable = command

    # LC_ALL=C to ensure English output, stderr=DEVNULL to prevent output
    # on stderr (Note: we don't have an example where the words we search
    # for are actually localized, but in theory some system could do so.)
    env = dict(os.environ)
    env['LC_ALL'] = 'C'
    cmd = [executable] + shlex.split(args)
    # proc = check_output(cmd, stderr=DEVNULL)
    # return proc
    # Using this instead of check_output is for Python 2.6 compatibility
    process = Popen(cmd, stdout=PIPE, stderr=DEVNULL)
    output, unused_err = process.communicate()
    retcode = process.poll()
    if retcode:
        raise CalledProcessError(retcode, cmd, output=output)
    return output


def _find_mac(command, args, hw_identifiers, get_index):
    proc = _popen(command, args)
    for line in proc:
        words = str(line).lower().rstrip().split()
        for i in range(len(words)):
            if words[i] in hw_identifiers:
                word = words[get_index(i)]
                mac = int(word.replace(':', ''), 16)  # b':', b''
                if mac:
                    return mac


def _get_mac_main():
    # TODO: commandline interface
    pass
