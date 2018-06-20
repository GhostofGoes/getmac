# -*- coding: utf-8 -*-

import ctypes, os, re, sys, struct, socket, shlex, traceback
from warnings import warn
from subprocess import Popen, PIPE, CalledProcessError
try:
    from subprocess import DEVNULL  # Py3
except ImportError:
    DEVNULL = open(os.devnull, 'wb')  # Py2

__version__ = '0.2.1'
DEBUG = False

PY3 = sys.version_info[0] == 3
IS_WINDOWS = sys.platform == 'win32'  # TODO: improve windows detection
PATH = os.environ.get("PATH", os.defpath).split(os.pathsep)
if not IS_WINDOWS:
    PATH.extend(('/sbin', '/usr/sbin'))
ENV = dict(os.environ)
ENV['LC_ALL'] = 'C'  # Ensure English output

# TODO: ignore case?
MAC_RE_COLON = r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})'
MAC_RE_DASH = r'([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})'


# TODO: add ability to match case-insensitively
def get_mac_address(interface=None, ip=None, ip6=None,
                    hostname=None, network_request=True):
    """
    Get a Unicast IEEE 802 MAC-48 address from a local interface or remote host.

    You must only use one of the first four arguments. If none of the arguments
    are selected, the default network interface for the system will be used.

    Exceptions will be handled silently and returned as a None.
    For the time being, it assumes you are using Ethernet.

    NOTE: you MUST provide str-typed arguments, REGARDLESS of Python version.

    Args:
        interface (str): Name of a local network interface (e.g "Ethernet 3", "eth0", "ens32")
        ip (str): Canonical dotted decimal IPv4 address of a remote host (e.g 192.168.0.1)
        ip6 (str): Canonical shortened IPv6 address of a remote host (e.g ff02::1:ffe7:7f19)
        hostname (str): DNS hostname of a remote host (e.g "router1.mycorp.com", "localhost")
        network_request (bool): Ping a remote host to populate the ARP/NDP tables for IPv4/IPv6
    Returns:
        Lowercase colon-separated MAC address, or None if one could not be
        found or there was an error.
    """
    # Populate the ARP table using a simple ping
    if network_request and (ip or ip6 or hostname):
        try:
            if IS_WINDOWS:
                _popen("ping", "-n 1 %s" % ip if ip is not None else ip6)
            else:
                if ip is not None:  # IPv4
                    _popen("ping", "-c 1 %s" % ip)
                else:  # IPv6
                    _popen("ping6", "-c 1 %s" % ip6)
        # If network request fails, warn and continue onward
        except Exception:
            if DEBUG:
                traceback.print_exc()
            warn("Ping failed due to an exception. You should disable "
                 "these attempts by setting 'network_request' to "
                 "False on systems generating this warning.", RuntimeWarning)

    # Resolve hostname to an IP address
    if hostname:
        ip = socket.gethostbyname(hostname)
        # TODO: IPv6 support
        #   Use getaddrinfo instead of gethostbyname
        #   This would handle case of an IPv6 host

    # Setup the address hunt based on the arguments specified
    if ip6:
        if not socket.has_ipv6:
            warn("Cannot get the MAC address of a IPv6 host: "
                 "IPv6 is not supported on this system", RuntimeWarning)
            return None
        to_find = ip6
        type_of_thing = 'ip6'
    elif ip:
        to_find = ip
        type_of_thing = 'ip'
    else:
        # Get MAC of a local interface
        type_of_thing = 'interface'
        if interface:
            to_find = interface

        # Default to finding MAC of the interface with the default route
        # TODO: function for determining default interface
        elif IS_WINDOWS:
            # TODO: default route OR first interface found windows
            to_find = 'Ethernet'
        else:
            # Try to use the IP command to get default interface
            # TODO: default interface
            try:
                to_find = _unix_default_interface_ip_command()
            except Exception:
                to_find = None
            if to_find is None:
                to_find = 'eth0'

    mac = _hunt_for_mac(to_find, type_of_thing, net_ok=network_request)
    if DEBUG:
        print("Raw MAC found: ", mac)

    # Check and format the result to be lowercase, colon-separated
    if mac is not None:
        mac = str(mac)
        if PY3:  # Strip bytestring conversion artifacts
            mac = mac.replace("b'", '').replace("'", '')\
                     .replace('\\n', '').replace('\\r', '')
        mac = mac.strip().lower().replace(' ', '').replace('-', ':')

        # Fix cases where there are no colons
        if len(mac) == 12:
            # Source: https://stackoverflow.com/a/3258612/2214380
            mac = ':'.join(mac[i:i + 2] for i in range(0, len(mac), 2))

        # MAC address should ALWAYS be 17 characters with the colons
        if len(mac) != 17:
            mac = None
    return mac


def _windows_get_remote_mac(host):
    # Source: https://goo.gl/ymhZ9p
    # Requires windows 2000 or newer

    # Check for API availability
    send_arp = ctypes.windll.Iphlpapi.SendARP

    # Doesn't work with loopbacks, but let's try and help.
    if host == '127.0.0.1' or host.lower() == 'localhost':
        host = socket.gethostname()

    # gethostbyname blocks, so use it wisely.
    try:
        inetaddr = ctypes.windll.wsock32.inet_addr(host)
        if inetaddr in (0, -1):
            raise Exception
    except Exception:
        hostip = socket.gethostbyname(host)
        inetaddr = ctypes.windll.wsock32.inet_addr(hostip)

    buffer = ctypes.c_buffer(6)
    addlen = ctypes.c_ulong(ctypes.sizeof(buffer))

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


# TODO: IPv6?
def _unix_fcntl_by_interface(interface):
    # Source: https://stackoverflow.com/a/4789267/2214380
    import fcntl
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # TODO: ip6?
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', interface[:15]))
    return ':'.join(['%02x' % ord(char) for char in info[18:24]])


# TODO: UNICODE option needed for non-english locales? (Is LC_ALL working?)
def _hunt_for_mac(to_find, type_of_thing, net_ok=True):
    # Format of method lists
    # Tuple:    (regex, regex index, command, command args)
    # Function: function to call

    # Windows - Network Interface
    if IS_WINDOWS and type_of_thing == 'interface':
        methods = [
            # getmac - Connection Name
            (r'\r\n' + to_find + r'.*' + MAC_RE_DASH + r'.*\r\n', 0,
             'getmac', ['/v /fo TABLE /nh']),

            # ipconfig
            (to_find + r'(?:\n?[^\n]*){1,8}Physical Address[ .:]+'
             + MAC_RE_DASH + r'\r\n',
             0, 'ipconfig', ['/all']),

            # getmac - Network Adapter (the human-readable name)
            (r'\r\n.*' + to_find + r'.*' + MAC_RE_DASH + r'.*\r\n', 0,
             'getmac', ['/v /fo TABLE /nh']),

            # TODO: "netsh int ipv6"
            # TODO: getmac.exe
        ]

    # Windows - Remote Host
    elif IS_WINDOWS and type_of_thing in ['ip', 'ip6', 'hostname']:
        esc = re.escape(to_find)
        methods = [
            # TODO: "netsh int ipv6 show neigh"
            # TODO: "arping"
            # TODO: getmac.exe
        ]

        # Add methods that make network requests
        if net_ok and type_of_thing != 'ip6':
            methods.append(_windows_get_remote_mac)

    # Non-Windows - Network Interface
    elif type_of_thing == 'interface':
        methods = [
            lambda x: _popen('cat', '/sys/class/net/' + x + '/address'),

            _unix_fcntl_by_interface,

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
            (MAC_RE_COLON, 0,
             'networksetup', ['-getmacaddress %s' % to_find]),

            # ifconfig
            (to_find + r'.*(HWaddr) ' + MAC_RE_COLON,
             1, 'ifconfig', ['', '-a', '-v']),

            # Mac OS X
            (to_find + r'.*(ether) ' + MAC_RE_COLON,
             1, 'ifconfig', ['']),

            # Tru64 ('-av')
            (to_find + r'.*(Ether) ' + MAC_RE_COLON,
             1, 'ifconfig', ['-av']),

            # HP-UX
            lambda x: _find_mac('lanscan', '-ai',
                                ['lan0' if x == 'eth0' else x], lambda i: 0),
        ]

    # Non-Windows - Remote Host
    elif type_of_thing in ['ip', 'ip6', 'hostname']:
        esc = re.escape(to_find)
        methods = [
            (esc + r'.*' + MAC_RE_COLON,
             0, 'cat', ['/proc/net/arp']),

            (r'\(' + esc + r'\)\s+at\s+' + MAC_RE_COLON,
             0, 'arp', ['-an']),

            # Linux, FreeBSD and NetBSD
            lambda x: _find_mac('arp', '-an', [os.fsencode('(%s)' % x)],
                                lambda i: i + 2),
            # TODO: "ip neighbor show"
            # TODO: "arping"
        ]
    else:  # This should never happen
        return None

    # We try every function and see if it returned a MAC address
    # If it returns None or raises an exception,
    # we continue and try the next function
    found = None
    for m in methods:
        try:
            if isinstance(m, tuple):
                for arg in m[3]:
                    found = _search(m[0], _popen(m[2], arg), m[1])
                    if DEBUG:
                        print("%s %s: %s" % (m[2], arg, found))
            elif callable(m):
                found = m(to_find)
                if DEBUG:
                    print("%s: %s" % (m.__name__, found))
        except Exception as ex:
            if DEBUG:
                print("Exception: ", str(ex))
                traceback.print_exc()
            continue
        if found:
            break
    return found


def _unix_default_interface_ip_command():
    return _search(r'.*dev ([0-9a-z]*)',
                   _popen('ip', 'route get 0.0.0.0'))


# TODO
def _unix_default_interface_route_command():
    return _search(r'.*' + re.escape('0.0.0.0') + r'.*([0-9a-z]*)\n',
                   _popen('route', '-n'), group_index=1)


def _search(regex, text, group_index=0):
    match = re.search(regex, text)
    if match:
        return match.groups()[group_index]
    else:
        return None


def _popen(command, args):
    for directory in PATH:
        executable = os.path.join(directory, command)
        if (os.path.exists(executable) and
                os.access(executable, os.F_OK | os.X_OK) and
                not os.path.isdir(executable)):
            break
    else:
        executable = command
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

    if PY3 and isinstance(output, bytes):
        return str(output, 'utf-8')
    else:
        return str(output)


def _find_mac(command, args, hw_identifiers, get_index):
    proc = _popen(command, args)
    for line in proc:
        words = str(line).lower().rstrip().split()
        for i in range(len(words)):
            if words[i] in hw_identifiers:
                word = words[get_index(i)]
                mac = int(word.replace(':', ''), 16)
                if mac:
                    return mac
