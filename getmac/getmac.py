# -*- coding: utf-8 -*-

"""Get the MAC address of remote hosts or network interfaces using Python.

It provides a platform-independant interface to get the MAC addresses of:

* System network interfaces (by interface name)
* Remote hosts on the local network (by IPv4/IPv6 address or hostname)

It provides one function: `get_mac_address()`

Examples:

    from getmac import get_mac_address
    eth_mac = get_mac_address(interface="eth0")
    win_mac = get_mac_address(interface="Ethernet 3")
    ip_mac = get_mac_address(ip="192.168.0.1")
    ip6_mac = get_mac_address(ip6="::1")
    host_mac = get_mac_address(hostname="localhost")
    updated_mac = get_mac_address(ip="10.0.0.1", network_request=True)"""

import ctypes, os, re, sys, struct, socket, shlex, traceback, platform
from warnings import warn
from subprocess import Popen, PIPE, CalledProcessError
try:
    from subprocess import DEVNULL  # Py3
except ImportError:
    DEVNULL = open(os.devnull, 'wb')  # Py2

__version__ = '0.5.0'
DEBUG = 0
PORT = 55555

PY2 = sys.version_info[0] == 2
_SYST = platform.system()
if _SYST == 'Windows':
    IS_WINDOWS = True
elif _SYST == 'Java':
    IS_WINDOWS = os.sep == '\\'
else:
    IS_WINDOWS = False

if not IS_WINDOWS and 'Microsoft' in platform.version():
    IS_WSL = True
else:
    IS_WSL = False


PATH = os.environ.get('PATH', os.defpath).split(os.pathsep)
if not IS_WINDOWS:
    PATH.extend(('/sbin', '/usr/sbin'))

ENV = dict(os.environ)
ENV['LC_ALL'] = 'C'  # Ensure ASCII output so we parse correctly

IP4 = 0
IP6 = 1
INTERFACE = 2
HOSTNAME = 3

MAC_RE_COLON = r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})'
MAC_RE_DASH = r'([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})'
MAC_RE_DARWIN = r'([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})'


def get_mac_address(interface=None, ip=None, ip6=None,
                    hostname=None, network_request=True):
    """Get a Unicast IEEE 802 MAC-48 address from a local interface or remote host.

    You must only use one of the first four arguments. If none of the arguments
    are selected, the default network interface for the system will be used.

    Exceptions will be handled silently and returned as a None.
    For the time being, it assumes you are using Ethernet.

    NOTES:
    * You MUST provide str-typed arguments, REGARDLESS of Python version.
    * localhost/127.0.0.1 will always return '00:00:00:00:00:00'

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
        found or there was an error."""
    if (hostname and hostname == 'localhost') or (ip and ip == '127.0.0.1'):
        return '00:00:00:00:00:00'

    if DEBUG >= 2:
        print("IS_WINDOWS\t%s\nIS_WSL\t\t%s" % (str(IS_WINDOWS), str(IS_WSL)))

    # Resolve hostname to an IP address
    if hostname:
        ip = socket.gethostbyname(hostname)

    # Populate the ARP table by sending a empty UDP packet to a high port
    if network_request and (ip or ip6):
        try:
            if ip:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.sendto(b'', (ip, PORT))
            else:
                s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                s.sendto(b'', (ip6, PORT))
        except Exception:
            if DEBUG:
                print("ERROR: Failed to send ARP table population packet")
            if DEBUG >= 2:
                traceback.print_exc()

    # Setup the address hunt based on the arguments specified
    if ip6:
        if not socket.has_ipv6:
            warn("Cannot get the MAC address of a IPv6 host: "
                 "IPv6 is not supported on this system", RuntimeWarning)
            return None
        elif ':' not in ip6:
            warn("Invalid IPv6 address: %s" % ip6, RuntimeWarning)
            return None
        to_find = ip6
        typ = IP6
    elif ip:
        to_find = ip
        typ = IP4
    else:
        typ = INTERFACE
        if interface:
            to_find = interface
        # Default to finding MAC of the interface with the default route
        else:
            to_find = _hunt_default_iface()
            if to_find is None:
                if IS_WINDOWS:
                    to_find = 'Ethernet'
                else:
                    to_find = 'en0'

    mac = _hunt_for_mac(to_find, typ, net_ok=network_request)
    if DEBUG:
        print("Raw MAC found: %s" % mac)

    # Check and format the result to be lowercase, colon-separated
    if mac is not None:
        mac = str(mac)
        if not PY2:  # Strip bytestring conversion artifacts
            mac = mac.replace("b'", '').replace("'", '')\
                     .replace('\\n', '').replace('\\r', '')
        mac = mac.strip().lower().replace(' ', '').replace('-', ':')

        # Fix cases where there are no colons
        if ':' not in mac and len(mac) == 12:
            if DEBUG:
                print("Adding colons to MAC %s" % mac)
            mac = ':'.join(mac[i:i + 2] for i in range(0, len(mac), 2))

        # Pad single-character octets with a leading zero (e.g Darwin's ARP output)
        elif len(mac) < 17:
            if DEBUG:
                print("Length of MAC %s is %d, padding single-character "
                      "octets with zeros" % (mac, len(mac)))
            parts = mac.split(':')
            new_mac = []
            for part in parts:
                if len(part) == 1:
                    new_mac.append('0' + part)
                else:
                    new_mac.append(part)
            mac = ':'.join(new_mac)

        # MAC address should ALWAYS be 17 characters before being returned
        if len(mac) != 17:
            if DEBUG:
                print("ERROR: MAC %s is not 17 characters long!" % mac)
            mac = None
    return mac


def _search(regex, text, group_index=0):
    match = re.search(regex, text)
    if match:
        return match.groups()[group_index]


def _popen(command, args):
    for directory in PATH:
        executable = os.path.join(directory, command)
        if (os.path.exists(executable) and
                os.access(executable, os.F_OK | os.X_OK) and
                not os.path.isdir(executable)):
            break
    else:
        executable = command
    if DEBUG >= 3:
        print("Running: '%s %s'" % (executable, args))
    return _call_proc(executable, args)


def _call_proc(executable, args):
    if IS_WINDOWS:
        cmd = executable + ' ' + args
    else:
        cmd = [executable] + shlex.split(args)

    # Popen instead of check_output() for Python 2.6 compatibility
    process = Popen(cmd, stdout=PIPE, stderr=DEVNULL, env=ENV)
    output, unused_err = process.communicate()
    retcode = process.poll()
    if retcode:
        raise CalledProcessError(retcode, cmd, output=output)

    if not PY2 and isinstance(output, bytes):
        return str(output, 'utf-8')
    else:
        return str(output)


def _windows_ctypes_host(host):
    if not PY2:  # Convert to bytes on Python 3+ (Fixes #7)
        host = host.encode()
    try:
        inetaddr = ctypes.windll.wsock32.inet_addr(host)
        if inetaddr in (0, -1):
            raise Exception
    except Exception:
        hostip = socket.gethostbyname(host)
        inetaddr = ctypes.windll.wsock32.inet_addr(hostip)

    buffer = ctypes.c_buffer(6)
    addlen = ctypes.c_ulong(ctypes.sizeof(buffer))

    send_arp = ctypes.windll.Iphlpapi.SendARP
    if send_arp(inetaddr, 0, ctypes.byref(buffer), ctypes.byref(addlen)) != 0:
        return None

    # Convert binary data into a string.
    macaddr = ''
    for intval in struct.unpack('BBBBBB', buffer):
        if intval > 15:
            replacestr = '0x'
        else:
            replacestr = 'x'
        macaddr = ''.join([macaddr, hex(intval).replace(replacestr, '')])
    return macaddr


def _fcntl_iface(iface):
    import fcntl
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # 0x8927 = SIOCGIFADDR
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', iface[:15]))
    return ':'.join(['%02x' % ord(char) for char in info[18:24]])


def _psutil_iface(iface):
    import psutil
    nics = psutil.net_if_addrs()
    if iface in nics:
        nic = nics[iface]
        for i in nic:
            if i.family == psutil.AF_LINK:
                return i.address


def _netifaces_iface(iface):
    """This method does not work on Windows."""
    import netifaces
    return netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]['addr']


def _scapy_ip(ip):
    """Requires root permissions on POSIX platforms.
    Windows does not have this limitation."""
    from scapy.layers.l2 import getmacbyip
    return getmacbyip(ip)


def _scapy_iface(iface):
    from scapy.layers.l2 import get_if_hwaddr
    if IS_WINDOWS:
        from scapy.arch.windows import get_windows_if_list
        interfaces = get_windows_if_list()
        for i in interfaces:
            if any(iface in i[x] for x in ['name', 'netid', 'description', 'win_index']):
                return i['mac']
    # Do not put an 'else' here!
    return get_if_hwaddr(iface)


def _uuid_ip(ip):
    from uuid import _arp_getnode
    backup = socket.gethostbyname
    try:
        socket.gethostbyname = lambda x: ip
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


def _uuid_lanscan_iface(iface):
    if not PY2:
        iface = bytes(iface)
    mac = __import__('uuid')._find_mac('lanscan', '-ai', [iface], lambda i: 0)
    if mac:
        return _uuid_convert(mac)


def _uuid_convert(mac):
    return ':'.join(('%012X' % mac)[i:i+2] for i in range(0, 12, 2))


def _hunt_for_mac(to_find, type_of_thing, net_ok=True):
    """Format of method lists:
    Tuple:  (regex, regex index, command, command args)
            Command args is a list of strings to attempt to use as arguments
    lambda: Function to call"""
    if not PY2 and isinstance(to_find, bytes):
        to_find = str(to_find, 'utf-8')

    # Windows - Network Interface
    if IS_WINDOWS and type_of_thing == INTERFACE:
        methods = [
            # getmac - Connection Name
            (r'\r\n' + to_find + r'.*' + MAC_RE_DASH + r'.*\r\n',
             0, 'getmac.exe', ['/NH /V']),

            # ipconfig
            (to_find + r'(?:\n?[^\n]*){1,8}Physical Address[ .:]+' + MAC_RE_DASH + r'\r\n',
             0, 'ipconfig.exe', ['/all']),

            # getmac - Network Adapter (the human-readable name)
            (r'\r\n.*' + to_find + r'.*' + MAC_RE_DASH + r'.*\r\n',
             0, 'getmac.exe', ['/NH /V']),

            # wmic - WMI command line utility
            lambda x: _popen('wmic.exe', 'nic where "NetConnectionID = \'%s\'" get '
                                         'MACAddress /value' % x).strip().partition('=')[2],

            _psutil_iface,
            _scapy_iface,
        ]

    # Windows - Remote Host
    elif (IS_WINDOWS or IS_WSL) and type_of_thing in [IP4, IP6, HOSTNAME]:
        methods = [
            # arp -a - Parsing result with a regex
            (MAC_RE_DASH, 0, 'arp.exe', ['-a %s' % to_find]),

            _scapy_ip,
        ]

        # Add methods that make network requests
        if net_ok and type_of_thing != IP6 and not IS_WSL:
            methods.insert(1, _windows_ctypes_host)

    # Non-Windows - Network Interface
    elif type_of_thing == INTERFACE:
        methods = [
            lambda x: _popen('cat', '/sys/class/net/' + x + '/address'),

            _fcntl_iface,

            # Fast ifconfig
            (r'HWaddr ' + MAC_RE_COLON,
             0, 'ifconfig', [to_find]),

            # Fast Mac OS X
            (r'ether ' + MAC_RE_COLON,
             0, 'ifconfig', [to_find]),

            # netstat
            (to_find + r'.*(HWaddr) ' + MAC_RE_COLON,
             1, 'netstat', ['-iae']),

            # ip link (Don't use 'list' due to SELinux [Android 24+])
            (to_find + r'.*\n.*link/ether ' + MAC_RE_COLON,
             0, 'ip', ['link %s' % to_find, 'link']),

            # Quick attempt on Mac OS X
            (MAC_RE_COLON,
             0, 'networksetup', ['-getmacaddress %s' % to_find]),

            # ifconfig
            (to_find + r'.*(HWaddr) ' + MAC_RE_COLON,
             1, 'ifconfig', ['', '-a', '-v']),

            # Mac OS X
            (to_find + r'.*(ether) ' + MAC_RE_COLON,
             1, 'ifconfig', ['']),

            # Tru64 ('-av')
            (to_find + r'.*(Ether) ' + MAC_RE_COLON,
             1, 'ifconfig', ['-av']),

            _netifaces_iface,
            _psutil_iface,
            _scapy_iface,
            _uuid_lanscan_iface,
        ]

    # Non-Windows - Remote Host
    elif type_of_thing in [IP4, IP6, HOSTNAME]:
        esc = re.escape(to_find)
        methods = [
            # Need a space, otherwise a search for 192.168.16.2
            # will match 192.168.16.254 if it comes first!
            (esc + r' .+' + MAC_RE_COLON,
             0, 'cat', ['/proc/net/arp']),

            lambda x: _popen('ip', 'neighbor show %s' % x)
                .partition(x)[2].partition('lladdr')[2].strip().split()[0],

            # -a: BSD-style format
            # -n: shows numerical addresses
            (r'\(' + esc + r'\)\s+at\s+' + MAC_RE_COLON,
             0, 'arp', [to_find, '-an', '-an %s' % to_find]),

            # Darwin (OSX) oddness
            (r'\(' + esc + r'\)\s+at\s+' + MAC_RE_DARWIN,
             0, 'arp', [to_find, '-a', '-a %s' % to_find]),

            _uuid_ip,
            _scapy_ip,
            lambda x: __import__('arpreq').arpreq(x),
        ]
    else:
        warn("ERROR: reached end of _hunt_for_mac() if-else chain!", RuntimeError)
        return None
    return _try_methods(methods, to_find)


def _try_methods(methods, to_find=None):
    """We try every method and see if it returned a MAC address. If it returns
    None or raises an exception, we continue and try the next method."""
    found = None
    for m in methods:
        try:
            if isinstance(m, tuple):
                for arg in m[3]:  # list(str)
                    if DEBUG:
                        print("Trying: '%s %s'" % (m[2], arg))
                    # Arguments: (regex, _popen(command, arg), regex index)
                    found = _search(m[0], _popen(m[2], arg), m[1])
                    if DEBUG:
                        print("Result: %s\n" % found)
            elif callable(m):
                if DEBUG:
                    print("Trying: '%s' (to_find: '%s')" % (m.__name__, str(to_find)))
                if to_find is not None:
                    found = m(to_find)
                else:
                    found = m()
                if DEBUG:
                    print("Result: %s\n" % found)
        except Exception as ex:
            if DEBUG:
                print("Exception: %s" % str(ex))
            if DEBUG >= 2:
                traceback.print_exc()
            continue
        if found:
            break
    return found


def _hunt_default_iface():
    if IS_WINDOWS:
        methods = []
    else:
        # NOTE: for now, we check the default interface for WSL using the
        # same methods as POSIX, since those parts of the net stack work fine.
        methods = [
            lambda: _popen('route', '-n').partition('0.0.0.0')[2].partition('\n')[0].split()[-1],
            lambda: _popen('ip', 'route list 0/0').partition('dev')[2].partition('proto')[0].strip(),
            lambda: list(__import__('netifaces').gateways()['default'].values())[0][1],
        ]
    return _try_methods(methods=methods)


__all__ = ['get_mac_address']
