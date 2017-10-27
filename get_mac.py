#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""
Cross-platform Pure-Python 2/3 cross-compatible tool to get a damn MAC address.

It enables you to get the MAC addresses of:
    A local network interface
    A remote host
    Your neighbor
    Your dog
    Your mother

It provides one function: get_mac_address()


Sources:
    Majority of the methods used to attempt, the core logic (notably "getters"),
    and a few others things are attributed to the CPython project and it's UUID code.
    Source: https://github.com/python/cpython/blob/master/Lib/uuid.py
"""

# Feature TODO
#   interface
#   ip
#   ip6
#   make_arp_request
#   docstrings
#   comments
#   slim down
#   speed up
#   remove print statements OR log errors to stderr OR use logging


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
#   Sick ACII Cinema capture of usage? (for lulz)
#   Emoji
#   memes
#   ???
#   profit


from __future__ import print_function
import sys
import os
import re
import struct


def get_mac_address(interface=None, ip=None, ip6=None, make_arp_request=False):
    # TODO: docstring

    # Get MAC of a IPv4 remote host
    if ip is not None:
        pass

    # Get MAC of a IPv6 remote host
    elif ip6 is not None:
        pass

    # Get MAC of a local interface
    else:
        if interface is not None:
            iface = str(interface)
        else:
            iface = 'default'  # TODO

        # TODO: use IP of interface for functions that require an IP


        if sys.platform == 'win32':
            getters = [_windll_getnode, _netbios_getnode, _ipconfig_getnode]
        else:
            getters = [_unix_getnode, _ifconfig_getnode, _ip_getnode,
                       _arp_getnode, _lanscan_getnode, _netstat_getnode]

        for getter in getters:
            try:
                _node = getter()
            except Exception as ex:
                print("Exception: %s" % ex.message)
                continue
            if _node is not None:
                return _node


# ***************************
# *-#-*     Windows     *-#-*
# ***************************


# ** Windows: Hosts **


# Source: https://code.activestate.com/recipes/347812-get-the-mac-address-of-a-remote-computer/
def _get_remote_mac(host):
    """ Returns the MAC address of a network host, requires >= WIN2K. """
    import ctypes
    import socket
    import struct

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

    return macaddr.upper()


# ** Windows: Interfaces **


def _windll_getnode():
    """Get the hardware address on Windows using ctypes."""
    import ctypes
    # _load_system_functions()
    # _buffer = ctypes.create_string_buffer(16)
    # if _UuidCreate(_buffer) == 0:
    #     print("WinDLL Buffer: ", _buffer.raw)
    #     # return UUID(bytes=bytes_(_buffer.raw)).node


# TODO: extend to specific interface
def _ipconfig_getnode():
    """Get the hardware address on Windows by running ipconfig.exe."""
    dirs = ['', r'c:\windows\system32', r'c:\winnt\system32']
    try:
        import ctypes
        buffer = ctypes.create_string_buffer(300)
        ctypes.windll.kernel32.GetSystemDirectoryA(buffer, 300)
        dirs.insert(0, buffer.value.decode('mbcs'))
    except:
        pass
    for dir in dirs:
        try:
            pipe = os.popen(os.path.join(dir, 'ipconfig') + ' /all')
        except OSError:
            continue
        with pipe:
            for line in pipe:
                value = line.split(':')[-1].strip().lower()
                if re.match('([0-9a-f][0-9a-f]-){5}[0-9a-f][0-9a-f]', value):
                    return int(value.replace('-', ''), 16)
    print("failed ipconfig")


# TODO: extend to specific interface
def _netbios_getnode():
    """Get the hardware address on Windows using NetBIOS calls.
    See http://support.microsoft.com/kb/118623 for details.

    Requires: pywin32 (pip install pypiwin32)
    """
    import win32wnet, netbios
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
        bytes = status.adapter_address[:6]
        if len(bytes) != 6:
            continue
        return int.from_bytes(bytes, 'big')
    print("Failed netbios")


# ******************************
# *-#-*     Unix/Linux     *-#-*
# ******************************


# Get MAC of a specific local interface on Linux
# Source: https://stackoverflow.com/a/4789267/2214380
def _linux_iface_addr(ifname):
    import fcntl
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', ifname[:15]))
    return ':'.join(['%02x' % ord(char) for char in info[18:24]])


def _unix_getnode():
    """Get the hardware address on Unix using the _uuid extension module
    or ctypes."""
    pass
    # _load_system_functions()
    # uuid_time, _ = _generate_time_safe()
    # print("unix_getnode: ", uuid_time)
    # return UUID(bytes=uuid_time).node


def _ifconfig_getnode(interface):
    """Get the hardware address on Unix by running ifconfig."""
    # This works on Linux ('' or '-a'), Tru64 ('-av'), but not all Unixes.
    for args in ('', '-a', '-v'):
        # mac = _find_mac('ifconfig', args, [b'hwaddr', b'ether'], lambda i: i+1)
        proc = _popen('ifconfig', [args])
        if not proc:
            return
        with proc:
            output = str(proc.stdout)
            match = re.search(
                re.escape(interface) + r'.*(HWaddr|Ether) ([0-9a-f]{2}(?::[0-9a-f]{2}){5})', output)
            if match:
                mac = str(match.groups()[1])
                print("Found interface %s in ifconfig. Result: %s" % (interface, mac))
                return mac
            else:
                print("Did not find interface %s in ifconfig." % interface)
                continue
    return None


def _ip_getnode(interface):
    """Get the hardware address on Unix by running "ip link list"."""
    # This works on Linux with iproute2.
    # mac = _find_mac('ip', 'link list', [b'link/ether'], lambda i: i+1)
    proc = _popen('ip', ['link', 'list'])
    if not proc:
        return
    with proc:
        output = str(proc.stdout)
        match = re.search(
            re.escape(interface) + r'.*\n.*link/ether ([0-9a-f]{2}(?::[0-9a-f]{2}){5})', output)
        if match:
            mac = str(match.groups()[0])
            print("Found interface %s in ip link list. Result: %s" % (interface, mac))
            return mac
        else:
            print("Did not find interface %s in ip link list." % interface)
            return None


# TODO: extend to specific interface
def _arp_getnode(ip):
    """Get the hardware address on Unix by running arp."""
    # Try getting the MAC addr from arp based on our IP address (Solaris).
    # TODO: os.fsencode? wat?
    return _find_mac('arp', '-an', [ip], lambda i: -1)  # os.fsencode(ip)


# TODO: extend to specific interface
def _lanscan_getnode():
    """Get the hardware address on Unix by running lanscan."""
    # This might work on HP-UX.
    return _find_mac('lanscan', '-ai', [b'lan0'], lambda i: 0)


# TODO: extend to specific interface
def _netstat_getnode():
    """Get the hardware address on Unix by running netstat."""
    # This might work on AIX, Tru64 UNIX.
    try:
        proc = _popen('netstat', '-ia')
        if not proc:
            return
        with proc:
            words = proc.stdout.readline().rstrip().split()
            try:
                i = words.index(b'Address')
            except ValueError:
                return
            for line in proc.stdout:
                try:
                    words = line.rstrip().split()
                    word = words[i]
                    if len(word) == 17 and word.count(b':') == 5:
                        mac = int(word.replace(b':', b''), 16)
                        if mac:
                            return mac
                except (ValueError, IndexError):
                    pass
    except OSError:
        pass


# ***********************************
# *-#-*     Utilities/Other     *-#-*
# ***********************************


def _popen(command, *args):
    import os, shutil, subprocess
    executable = shutil.which(command)
    if executable is None:
        path = os.pathsep.join(('/sbin', '/usr/sbin'))
        executable = shutil.which(command, path=path)
        if executable is None:
            return None
    # LC_ALL=C to ensure English output, stderr=DEVNULL to prevent output
    # on stderr (Note: we don't have an example where the words we search
    # for are actually localized, but in theory some system could do so.)
    env = dict(os.environ)
    env['LC_ALL'] = 'C'
    proc = subprocess.Popen((executable,) + args,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL,
                            env=env)
    return proc


def _find_mac(command, args, hw_identifiers, get_index):
    try:
        proc = _popen(command, *args.split())
        if not proc:
            return
        with proc:
            for line in proc.stdout:
                words = line.lower().rstrip().split()
                for i in range(len(words)):
                    if words[i] in hw_identifiers:
                        try:
                            word = words[get_index(i)]
                            mac = int(word.replace(b':', b''), 16)
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


# !/usr/bin/env python


"""
Cross-platform Pure-Python 2/3 cross-compatible tool to get a damn MAC address. 

It enables you to get the MAC addresses of:
    A local network interface
    A remote host
    Your neighbor
    Your dog
    Your mother

It provides one function: get_mac_address()


Sources:
    Majority of the methods used to attempt, the core logic (notably "getters"), 
    and a few others things are attributed to the CPython project and it's UUID code.
    Source: https://github.com/python/cpython/blob/master/Lib/uuid.py


Supported platforms:


Tested platforms:


Supported Python versions:

Unsupported/unimplemented platforms:

"""

import sys
import os
import re
import struct
from __future__ import print_function


# TODO list
#   ip addr vs ifconfig?
#   IPv6?
#   Android
#   OpenBSD + FreeBSD
#   Solaris?

def get_mac_address(interface=None, ip=None, ip6=None, make_arp_request=False):
    # TODO: docstring

    # Get MAC of a IPv4 remote host
    if ip is not None:
        pass

    # Get MAC of a IPv6 remote host
    elif ip6 is not None:
        pass

    # Get MAC of a local interface
    else:
        if interface is not None:
            iface = str(interface)
        else:
            iface = 'default'  # TODO

        # TODO: use IP of interface for functions that require an IP


        if sys.platform == 'win32':
            getters = [_windll_getnode, _netbios_getnode, _ipconfig_getnode]
        else:
            getters = [_unix_getnode, _ifconfig_getnode, _ip_getnode,
                       _arp_getnode, _lanscan_getnode, _netstat_getnode]

        for getter in getters:
            try:
                _node = getter()
            except Exception as ex:
                print("Exception: %s" % ex.message)
                continue
            if _node is not None:
                return _node


# ***************************
# *-#-*     Windows     *-#-*
# ***************************


# ** Windows: Hosts **


# Source: https://code.activestate.com/recipes/347812-get-the-mac-address-of-a-remote-computer/
def _get_remote_mac(host):
    """ Returns the MAC address of a network host, requires >= WIN2K. """
    import ctypes
    import socket
    import struct

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

    return macaddr.upper()


# ** Windows: Interfaces **


def _windll_getnode():
    """Get the hardware address on Windows using ctypes."""
    import ctypes
    # _load_system_functions()
    # _buffer = ctypes.create_string_buffer(16)
    # if _UuidCreate(_buffer) == 0:
    #     print("WinDLL Buffer: ", _buffer.raw)
    #     # return UUID(bytes=bytes_(_buffer.raw)).node


# TODO: extend to specific interface
def _ipconfig_getnode():
    """Get the hardware address on Windows by running ipconfig.exe."""
    dirs = ['', r'c:\windows\system32', r'c:\winnt\system32']
    try:
        import ctypes
        buffer = ctypes.create_string_buffer(300)
        ctypes.windll.kernel32.GetSystemDirectoryA(buffer, 300)
        dirs.insert(0, buffer.value.decode('mbcs'))
    except:
        pass
    for dir in dirs:
        try:
            pipe = os.popen(os.path.join(dir, 'ipconfig') + ' /all')
        except OSError:
            continue
        with pipe:
            for line in pipe:
                value = line.split(':')[-1].strip().lower()
                if re.match('([0-9a-f][0-9a-f]-){5}[0-9a-f][0-9a-f]', value):
                    return int(value.replace('-', ''), 16)
    print("failed ipconfig")


# TODO: extend to specific interface
def _netbios_getnode():
    """Get the hardware address on Windows using NetBIOS calls.
    See http://support.microsoft.com/kb/118623 for details.

    Requires: pywin32 (pip install pypiwin32)
    """
    import win32wnet, netbios
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
        bytes = status.adapter_address[:6]
        if len(bytes) != 6:
            continue
        return int.from_bytes(bytes, 'big')
    print("Failed netbios")


# ******************************
# *-#-*     Unix/Linux     *-#-*
# ******************************


# Get MAC of a specific local interface on Linux
# Source: https://stackoverflow.com/a/4789267/2214380
def _linux_iface_addr(ifname):
    import fcntl
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', ifname[:15]))
    return ':'.join(['%02x' % ord(char) for char in info[18:24]])


def _unix_getnode():
    """Get the hardware address on Unix using the _uuid extension module
    or ctypes."""
    pass
    # _load_system_functions()
    # uuid_time, _ = _generate_time_safe()
    # print("unix_getnode: ", uuid_time)
    # return UUID(bytes=uuid_time).node


def _ifconfig_getnode(interface):
    """Get the hardware address on Unix by running ifconfig."""
    # This works on Linux ('' or '-a'), Tru64 ('-av'), but not all Unixes.
    for args in ('', '-a', '-v'):
        # mac = _find_mac('ifconfig', args, [b'hwaddr', b'ether'], lambda i: i+1)
        proc = _popen('ifconfig', [args])
        if not proc:
            return
        with proc:
            output = str(proc.stdout)
            match = re.search(
                re.escape(interface) + r'.*(HWaddr|Ether) ([0-9a-f]{2}(?::[0-9a-f]{2}){5})', output)
            if match:
                mac = str(match.groups()[1])
                print("Found interface %s in ifconfig. Result: %s" % (interface, mac))
                return mac
            else:
                print("Did not find interface %s in ifconfig." % interface)
                continue
    return None


def _ip_getnode(interface):
    """Get the hardware address on Unix by running "ip link list"."""
    # This works on Linux with iproute2.
    # mac = _find_mac('ip', 'link list', [b'link/ether'], lambda i: i+1)
    proc = _popen('ip', ['link', 'list'])
    if not proc:
        return
    with proc:
        output = str(proc.stdout)
        match = re.search(
            re.escape(interface) + r'.*\n.*link/ether ([0-9a-f]{2}(?::[0-9a-f]{2}){5})', output)
        if match:
            mac = str(match.groups()[0])
            print("Found interface %s in ip link list. Result: %s" % (interface, mac))
            return mac
        else:
            print("Did not find interface %s in ip link list." % interface)
            return None


# TODO: extend to specific interface
def _arp_getnode(ip):
    """Get the hardware address on Unix by running arp."""
    # Try getting the MAC addr from arp based on our IP address (Solaris).
    # TODO: os.fsencode? wat?
    return _find_mac('arp', '-an', [ip], lambda i: -1)  # os.fsencode(ip)


# TODO: extend to specific interface
def _lanscan_getnode():
    """Get the hardware address on Unix by running lanscan."""
    # This might work on HP-UX.
    return _find_mac('lanscan', '-ai', [b'lan0'], lambda i: 0)


# TODO: extend to specific interface
def _netstat_getnode():
    """Get the hardware address on Unix by running netstat."""
    # This might work on AIX, Tru64 UNIX.
    try:
        proc = _popen('netstat', '-ia')
        if not proc:
            return
        with proc:
            words = proc.stdout.readline().rstrip().split()
            try:
                i = words.index(b'Address')
            except ValueError:
                return
            for line in proc.stdout:
                try:
                    words = line.rstrip().split()
                    word = words[i]
                    if len(word) == 17 and word.count(b':') == 5:
                        mac = int(word.replace(b':', b''), 16)
                        if mac:
                            return mac
                except (ValueError, IndexError):
                    pass
    except OSError:
        pass


# ***********************************
# *-#-*     Utilities/Other     *-#-*
# ***********************************


def _popen(command, *args):
    import os, shutil, subprocess
    executable = shutil.which(command)
    if executable is None:
        path = os.pathsep.join(('/sbin', '/usr/sbin'))
        executable = shutil.which(command, path=path)
        if executable is None:
            return None
    # LC_ALL=C to ensure English output, stderr=DEVNULL to prevent output
    # on stderr (Note: we don't have an example where the words we search
    # for are actually localized, but in theory some system could do so.)
    env = dict(os.environ)
    env['LC_ALL'] = 'C'
    proc = subprocess.Popen((executable,) + args,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL,
                            env=env)
    return proc


def _find_mac(command, args, hw_identifiers, get_index):
    try:
        proc = _popen(command, *args.split())
        if not proc:
            return
        with proc:
            for line in proc.stdout:
                words = line.lower().rstrip().split()
                for i in range(len(words)):
                    if words[i] in hw_identifiers:
                        try:
                            word = words[get_index(i)]
                            mac = int(word.replace(b':', b''), 16)
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
