# -*- coding: utf-8 -*-

import platform
import socket
import sys
import uuid

import pytest

from getmac import get_mac_address, getmac

PY2 = sys.version_info[0] == 2
MAC_RE_COLON = r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})'
MAC_RE_DASH = r'([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})'


def test_get_mac_address_localhost():
    assert get_mac_address(hostname='localhost') == '00:00:00:00:00:00'
    assert get_mac_address(ip='127.0.0.1') == '00:00:00:00:00:00'
    result = get_mac_address(hostname='localhost', network_request=False)
    assert result == '00:00:00:00:00:00'


def test_search(get_sample):
    text = get_sample('ifconfig.out')
    regex = r'HWaddr ' + MAC_RE_COLON
    assert getmac._search(regex, text, 0) == '74:d4:35:e9:45:71'


def test_popen(mocker):
    mocker.patch('getmac.getmac.PATH', [])
    m = mocker.patch('getmac.getmac._call_proc', return_value='SUCCESS')
    assert getmac._popen('TESTCMD', 'ARGS') == 'SUCCESS'
    m.assert_called_once_with('TESTCMD', 'ARGS')


def test_call_proc(mocker):
    mocker.patch('getmac.getmac.DEVNULL', 'DEVNULL')
    mocker.patch('getmac.getmac.ENV', 'ENV')

    mocker.patch('getmac.getmac.WINDOWS', True)
    m = mocker.patch('getmac.getmac.check_output', return_value='WINSUCCESS')
    assert getmac._call_proc('CMD', 'arg') == 'WINSUCCESS'
    m.assert_called_once_with('CMD' + ' ' + 'arg', stderr='DEVNULL', env='ENV')

    mocker.patch('getmac.getmac.WINDOWS', False)
    m = mocker.patch('getmac.getmac.check_output', return_value='YAY')
    assert getmac._call_proc('CMD', 'arg1 arg2') == 'YAY'
    m.assert_called_once_with(['CMD', 'arg1', 'arg2'], stderr='DEVNULL', env='ENV')


@pytest.mark.skipif(platform.system() != 'Linux',
                    reason="Can't reliably mock fcntl on non-Linux platforms")
def test_fcntl_iface(mocker):
    data = b'enp3s0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00t\xd45\xe9' \
           b'Es\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    mocker.patch('fcntl.ioctl', return_value=data)
    m = mocker.patch('socket.socket')
    assert getmac._fcntl_iface('enp3s0') == '74:d4:35:e9:45:73'
    m.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)


# Python 2.7.5 (CentOS 7) doesn't have this...
# The commit adding it: https://bit.ly/2Hnd7bN (no idea what release it was in)
@pytest.mark.skipif(not hasattr(uuid, '_arp_getnode'),
                    reason="This version of Python doesn't have _arp_getnode")
def test_uuid_ip(mocker):
    mocker.patch('uuid._arp_getnode', return_value=278094213753144)
    assert getmac._uuid_ip('10.0.0.1') == 'FC:EC:DA:D3:29:38'
    mocker.patch('uuid._arp_getnode', return_value=None)
    assert getmac._uuid_ip('10.0.0.1') is None
    assert getmac._uuid_ip('en0') is None


def test_uuid_lanscan_iface(mocker):
    mocker.patch('uuid._find_mac', return_value=2482700837424)
    assert getmac._uuid_lanscan_iface('en1') == '02:42:0C:80:62:30'
    mocker.patch('uuid._find_mac', return_value=None)
    assert getmac._uuid_lanscan_iface('10.0.0.1') is None
    assert getmac._uuid_lanscan_iface('en0') is None


def test_uuid_convert():
    assert getmac._uuid_convert(2482700837424) == '02:42:0C:80:62:30'
    assert getmac._uuid_convert(278094213753144) == 'FC:EC:DA:D3:29:38'


def test_read_sys_iface_file(mocker):
    mocker.patch('getmac.getmac._read_file', return_value='00:0c:29:b5:72:37\n')
    assert getmac._read_sys_iface_file('ens33') == '00:0c:29:b5:72:37\n'
    mocker.patch('getmac.getmac._read_file', return_value=None)
    assert getmac._read_sys_iface_file('ens33') is None


def test_read_arp_file(mocker, get_sample):
    data = get_sample('ubuntu_18.10/proc_net_arp.out')
    mocker.patch('getmac.getmac._read_file', return_value=data)
    assert getmac._read_arp_file('192.168.16.2') == '00:50:56:e1:a8:4a'
    assert getmac._read_arp_file('192.168.16.254') == '00:50:56:e8:32:3c'
    assert getmac._read_arp_file('192.168.95.1') == '00:50:56:c0:00:0a'
    assert getmac._read_arp_file('192.168.95.254') == '00:50:56:fa:b7:54'


def test_read_file_return(mocker, get_sample):
    data = get_sample('ifconfig.out')
    mock_open = mocker.mock_open(read_data=data)
    if PY2:
        mocker.patch('__builtin__.open', mock_open)
    else:
        mocker.patch('builtins.open', mock_open)
    assert getmac._read_file('ifconfig.out') == data
    mock_open.assert_called_once_with('ifconfig.out')


def test_read_file_not_exist():
    assert getmac._read_file('DOESNOTEXIST') is None


def test_fetch_ip_using_dns(mocker):
    m = mocker.patch('socket.socket')
    m.return_value.getsockname.return_value = ('1.2.3.4', 51327)
    assert getmac._fetch_ip_using_dns() == '1.2.3.4'
