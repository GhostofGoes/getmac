import io
import sys
import warnings
from os import path

import pytest

from getmac import get_mac_address, getmac

PY2 = sys.version_info[0] == 2
MAC_RE_COLON = r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})'
MAC_RE_DASH = r'([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})'


@pytest.fixture
def get_sample():
    def _get_sample(sample_path):
        sdir = path.realpath(path.join(path.dirname(__file__), '..', 'samples'))
        with io.open(path.join(sdir, sample_path), 'rt', newline='', encoding='utf-8') as f:
            return f.read()
    return _get_sample


# def test_linux_ifconfig(mocker, get_sample):
#     # content = get_sample('ifconfig.out')
#     getmac.getmac.WINDOWS = False
#     getmac.getmac.OSX = False
#     getmac.getmac.WSL = False
#     getmac.getmac.LINUX = True
#     # mocker.patch
#
#     assert '74:d4:35:e9:45:71' == getmac.get_mac_address(interface='eth0')


# def test_linux_ip_link(mocker, get_sample):
#     # content = get_sample('ip_link_list.out')
#     assert '74:d4:35:e9:45:71' == getmac.get_mac_address(interface='eth0')
#
#
# def test_osx_ifconfig(mocker, get_sample):
#     # content = get_sample(path.join('OSX', 'ifconfig.out'))
#     pass

def test_get_mac_address_localhost():
    host_res = get_mac_address(hostname='localhost')
    assert host_res == '00:00:00:00:00:00'

    ip_res = get_mac_address(ip='127.0.0.1')
    assert ip_res == '00:00:00:00:00:00'

    netreq_res = get_mac_address(hostname='localhost', network_request=False)
    assert netreq_res == '00:00:00:00:00:00'


def test_warn(mocker):
    mocker.patch('warnings.warn')
    getmac._warn("testing")
    warnings.warn.assert_called_once_with("testing", RuntimeWarning)


def test_search(get_sample):
    # group_index = 0
    text = get_sample('ifconfig.out')
    regex = r'HWaddr ' + MAC_RE_COLON
    result = getmac._search(regex, text, 0)
    assert result == '74:d4:35:e9:45:71'


def test_popen(mocker):
    pass


def test_call_proc(mocker):
    pass


def test_windows_ctypes_host(mocker):
    pass


def test_fcntl_iface(mocker):
    pass


def test_uuid_ip(mocker):
    pass


def test_uuid_lanscan_iface(mocker):
    pass


def test_uuid_convert():
    result = getmac._uuid_convert(2482700837424)
    assert result == '02:42:0C:80:62:30'


def test_read_sys_iface_file(mocker):
    pass


def test_read_arp_file(mocker):
    pass


def test_read_file_return(mocker, get_sample):
    data = get_sample('ifconfig.out')
    mock_open = mocker.mock_open(read_data=data)
    if PY2:
        mocker.patch('__builtin__.open', mock_open)
    else:
        mocker.patch('builtins.open', mock_open)
    result = getmac._read_file('ifconfig.out')
    mock_open.assert_called_once_with('ifconfig.out')
    assert result == data


def test_read_file_not_exist():
    assert getmac._read_file('DOESNOTEXIST') is None


def test_hunt_for_mac(mocker):
    pass


def test_try_methods(mocker):
    pass


def test_get_default_iface_linux(mocker):
    pass


def test_hunt_linux_default_iface(mocker):
    pass


def test_fetch_ip_using_dns(mocker):
    pass
