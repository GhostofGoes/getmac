# -*- coding: utf-8 -*-

import sys

from getmac import getmac

PY2 = sys.version_info[0] == 2
MAC_RE_COLON = r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})'
MAC_RE_DASH = r'([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})'


def test_linux_ifconfig(mocker, get_sample):
    mocker.patch('getmac.getmac.WINDOWS', False)
    mocker.patch('getmac.getmac.DARWIN', False)
    mocker.patch('getmac.getmac.BSD', False)
    mocker.patch('getmac.getmac.OPENBSD', False)
    mocker.patch('getmac.getmac.FREEBSD', False)
    mocker.patch('getmac.getmac.LINUX', True)
    mocker.patch('getmac.getmac.WSL', False)
    content = get_sample('ifconfig.out')
    mocker.patch('getmac.getmac._call_proc', return_value=content)
    assert '74:d4:35:e9:45:71' == getmac.get_mac_address(interface='eth0')


def test_linux_ip_link_list(mocker, get_sample):
    mocker.patch('getmac.getmac.WINDOWS', False)
    mocker.patch('getmac.getmac.DARWIN', False)
    mocker.patch('getmac.getmac.BSD', False)
    mocker.patch('getmac.getmac.OPENBSD', False)
    mocker.patch('getmac.getmac.FREEBSD', False)
    mocker.patch('getmac.getmac.LINUX', True)
    mocker.patch('getmac.getmac.WSL', False)
    content = get_sample('ip_link_list.out')
    mocker.patch('getmac.getmac._call_proc', return_value=content)
    assert '74:d4:35:e9:45:71' == getmac.get_mac_address(interface='eth0')


def test_ubuntu_1804_interface(mocker, get_sample):
    mocker.patch('getmac.getmac.WINDOWS', False)
    mocker.patch('getmac.getmac.DARWIN', False)
    mocker.patch('getmac.getmac.BSD', False)
    mocker.patch('getmac.getmac.OPENBSD', False)
    mocker.patch('getmac.getmac.FREEBSD', False)
    mocker.patch('getmac.getmac.LINUX', True)
    mocker.patch('getmac.getmac.WSL', False)

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

    # TODO: mock return value so we're hitting the right regex
    content = get_sample('ubuntu_18.04/ip_link.out')
    mocker.patch('getmac.getmac._call_proc', return_value=content)
    assert '00:0c:29:b5:72:37' == getmac.get_mac_address(interface='ens33')

    # TODO: going to need to do some mock.side_effect hacking here
    # content = get_sample('ubuntu_18.04/netstat_iae.out')
    # mocker.patch('getmac.getmac._call_proc', return_value=content)
    # assert '00:0c:29:b5:72:37' == getmac.get_mac_address(interface='ens33')


def test_ubuntu_1804_remote(mocker, get_sample):
    mocker.patch('getmac.getmac.WINDOWS', False)
    mocker.patch('getmac.getmac.DARWIN', False)
    mocker.patch('getmac.getmac.OPENBSD', False)
    mocker.patch('getmac.getmac.FREEBSD', False)
    mocker.patch('getmac.getmac.LINUX', True)
    mocker.patch('getmac.getmac.WSL', False)

    content = get_sample('ubuntu_18.04/arp_-a.out')
    mocker.patch('getmac.getmac._call_proc', return_value=content)
    assert '00:50:56:f1:4c:50' == getmac.get_mac_address(ip='192.168.16.2')

    # TODO: mock return value so we're hitting the right regex
    content = get_sample('ubuntu_18.04/arp_-an.out')
    mocker.patch('getmac.getmac._call_proc', return_value=content)
    assert '00:50:56:f1:4c:50' == getmac.get_mac_address(ip='192.168.16.2')

    content = get_sample('ubuntu_18.04/cat_proc-net-arp.out')
    mocker.patch('getmac.getmac._read_file', return_value=content)
    assert '00:50:56:f1:4c:50' == getmac.get_mac_address(ip='192.168.16.2')

    content = get_sample('ubuntu_18.04/ip_neighbor_show_192-168-16-2.out')
    mocker.patch('getmac.getmac._call_proc', return_value=content)
    assert '00:50:56:f1:4c:50' == getmac.get_mac_address(ip='192.168.16.2')

    # TODO: mock return value so we're hitting the right regex
    content = get_sample('ubuntu_18.04/ip_neighbor_show.out')
    mocker.patch('getmac.getmac._call_proc', return_value=content)
    assert '00:50:56:f1:4c:50' == getmac.get_mac_address(ip='192.168.16.2')


def test_windows_10_interface(mocker, get_sample):
    mocker.patch('getmac.getmac.WINDOWS', True)
    mocker.patch('getmac.getmac.DARWIN', False)
    mocker.patch('getmac.getmac.BSD', False)
    mocker.patch('getmac.getmac.OPENBSD', False)
    mocker.patch('getmac.getmac.FREEBSD', False)
    mocker.patch('getmac.getmac.LINUX', False)
    mocker.patch('getmac.getmac.WSL', False)

    content = get_sample('windows_10/getmac.out')
    mocker.patch('getmac.getmac._call_proc', return_value=content)
    assert '74:d4:35:e9:45:71' == getmac.get_mac_address(interface='Ethernet 2')

    content = get_sample('windows_10/ipconfig-all.out')
    mocker.patch('getmac.getmac._call_proc', return_value=content)
    assert '74:d4:35:e9:45:71' == getmac.get_mac_address(interface='Ethernet 3')

    content = get_sample('windows_10/wmic_nic.out')
    mocker.patch('getmac.getmac._call_proc', return_value=content)
    assert '00:ff:17:15:f8:c8' == getmac.get_mac_address(interface='Ethernet 3')


def test_darwin_interface(mocker, get_sample):
    mocker.patch('getmac.getmac.WINDOWS', False)
    mocker.patch('getmac.getmac.DARWIN', True)
    mocker.patch('getmac.getmac.BSD', False)
    mocker.patch('getmac.getmac.OPENBSD', False)
    mocker.patch('getmac.getmac.FREEBSD', False)
    mocker.patch('getmac.getmac.LINUX', False)

    content = get_sample('OSX/ifconfig.out')
    mocker.patch('getmac.getmac._call_proc', return_value=content)
    assert '2c:f0:ee:2f:c7:de' == getmac.get_mac_address(interface='en0')


def test_darwin_remote(mocker, get_sample):
    mocker.patch('getmac.getmac.WINDOWS', False)
    mocker.patch('getmac.getmac.DARWIN', True)
    mocker.patch('getmac.getmac.BSD', False)
    mocker.patch('getmac.getmac.OPENBSD', False)
    mocker.patch('getmac.getmac.FREEBSD', False)
    mocker.patch('getmac.getmac.LINUX', False)

    content = get_sample('OSX/arp_-a.out')
    mocker.patch('getmac.getmac._call_proc', return_value=content)
    assert '58:6d:8f:07:c9:94' == getmac.get_mac_address(ip='192.168.1.1')

    # TODO: mock return value so we're hitting the right regex
    content = get_sample('OSX/arp_-an.out')
    mocker.patch('getmac.getmac._call_proc', return_value=content)
    assert '58:6d:8f:07:c9:94' == getmac.get_mac_address(ip='192.168.1.1')


def test_openbsd_interface(mocker, get_sample):
    mocker.patch('getmac.getmac.WINDOWS', False)
    mocker.patch('getmac.getmac.DARWIN', False)
    mocker.patch('getmac.getmac.BSD', False)
    mocker.patch('getmac.getmac.OPENBSD', True)
    mocker.patch('getmac.getmac.FREEBSD', False)
    mocker.patch('getmac.getmac.LINUX', False)

    content = get_sample('openbsd_6/ifconfig.out')
    mocker.patch('getmac.getmac._call_proc', return_value=content)
    assert '08:00:27:18:64:56' == getmac.get_mac_address(interface='em0')

    # TODO: mock return value so we're hitting the right regex
    content = get_sample('openbsd_6/ifconfig_em0.out')
    mocker.patch('getmac.getmac._call_proc', return_value=content)
    assert '08:00:27:18:64:56' == getmac.get_mac_address(interface='em0')


def test_openbsd_remote(mocker, get_sample):
    mocker.patch('getmac.getmac.WINDOWS', False)
    mocker.patch('getmac.getmac.DARWIN', False)
    mocker.patch('getmac.getmac.BSD', True)
    mocker.patch('getmac.getmac.OPENBSD', True)
    mocker.patch('getmac.getmac.FREEBSD', False)
    mocker.patch('getmac.getmac.LINUX', False)

    content = get_sample('openbsd_6/arp_an.out')
    mocker.patch('getmac.getmac._call_proc', return_value=content)
    assert '52:54:00:12:35:02' == getmac.get_mac_address(ip='10.0.2.2')
    assert '52:54:00:12:35:03' == getmac.get_mac_address(ip='10.0.2.3')
    assert '08:00:27:18:64:56' == getmac.get_mac_address(ip='10.0.2.15')


def test_freebsd_interface(mocker, get_sample):
    mocker.patch('getmac.getmac.WINDOWS', False)
    mocker.patch('getmac.getmac.DARWIN', False)
    mocker.patch('getmac.getmac.BSD', True)
    mocker.patch('getmac.getmac.OPENBSD', False)
    mocker.patch('getmac.getmac.FREEBSD', True)
    mocker.patch('getmac.getmac.LINUX', False)

    content = get_sample('freebsd11/ifconfig_em0.out')
    mocker.patch('getmac.getmac._call_proc', return_value=content)
    assert '08:00:27:33:37:26' == getmac.get_mac_address(interface='em0')


def test_freebsd_remote(mocker, get_sample):
    mocker.patch('getmac.getmac.WINDOWS', False)
    mocker.patch('getmac.getmac.DARWIN', False)
    mocker.patch('getmac.getmac.BSD', True)
    mocker.patch('getmac.getmac.OPENBSD', False)
    mocker.patch('getmac.getmac.FREEBSD', True)
    mocker.patch('getmac.getmac.LINUX', False)

    content = get_sample('freebsd11/arp_10-0-2-2.out')
    mocker.patch('getmac.getmac._call_proc', return_value=content)
    assert '52:54:00:12:35:02' == getmac.get_mac_address(ip='10.0.2.2')
