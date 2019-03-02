# -*- coding: utf-8 -*-

import sys

from getmac import getmac

PY2 = sys.version_info[0] == 2
MAC_RE_COLON = r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})'
MAC_RE_DASH = r'([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})'


def test_linux_ifconfig(mocker, get_sample):
    mocker.patch('getmac.getmac.WINDOWS', False)
    mocker.patch('getmac.getmac.DARWIN', False)
    mocker.patch('getmac.getmac.OPENBSD', False)
    mocker.patch('getmac.getmac.LINUX', True)
    content = get_sample('ifconfig.out')
    mocker.patch('getmac.getmac._call_proc', return_value=content)
    assert '74:d4:35:e9:45:71' == getmac.get_mac_address(interface='eth0')


def test_linux_ip_link_list(mocker, get_sample):
    mocker.patch('getmac.getmac.WINDOWS', False)
    mocker.patch('getmac.getmac.DARWIN', False)
    mocker.patch('getmac.getmac.OPENBSD', False)
    mocker.patch('getmac.getmac.LINUX', True)
    content = get_sample('ip_link_list.out')
    mocker.patch('getmac.getmac._call_proc', return_value=content)
    assert '74:d4:35:e9:45:71' == getmac.get_mac_address(interface='eth0')


def test_ubuntu_1804_interface(mocker, get_sample):
    mocker.patch('getmac.getmac.WINDOWS', False)
    mocker.patch('getmac.getmac.DARWIN', False)
    mocker.patch('getmac.getmac.OPENBSD', False)
    mocker.patch('getmac.getmac.LINUX', True)

    content = get_sample('ubuntu_18.04/ifconfig_ens33.out')
    mocker.patch('getmac.getmac._call_proc', return_value=content)
    assert '00:0c:29:b5:72:37' == getmac.get_mac_address(interface='ens33')

    # TODO: going to need to do some mock.side_effect hacking here
    # content = get_sample('ubuntu_18.04/ifconfig.out')
    # mocker.patch('getmac.getmac._call_proc', return_value=content)
    # assert '00:0c:29:b5:72:37' == getmac.get_mac_address(interface='ens33')

    content = get_sample('ubuntu_18.04/ip_link_list.out')
    mocker.patch('getmac.getmac._call_proc', return_value=content)
    assert '00:0c:29:b5:72:37' == getmac.get_mac_address(interface='ens33')

    content = get_sample('ubuntu_18.04/ip_link.out')
    mocker.patch('getmac.getmac._call_proc', return_value=content)
    assert '00:0c:29:b5:72:37' == getmac.get_mac_address(interface='ens33')
