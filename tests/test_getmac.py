#!/usr/bin/env python

# http://multivax.com/last_question.html

"""Unit and functional tests for getmac."""

import unittest
import getmac
import io
from os import path
try:
    from unittest import mock
except ImportError:
    import mock

getmac.DEBUG = True


class MockHelper(object):
    @classmethod
    def load_sample(cls, filename):
        filename = path.realpath('%s/../samples/%s' % (path.dirname(__file__), filename))
        content = ''
        with io.open(filename, 'rt', newline='') as f:
            content = f.read()
        return content

    def __init__(self, platform_name, cmd, sample):
        self.platform_name = platform_name
        self.cmd = cmd
        self.sample = sample

    def create_side_effect(self, cmd, sample):
        def side_effect(params, *args, **kwargs):
            output = None
            retcode = 0
            params = ' '.join(params) if isinstance(params, list) else params
            if cmd in params:
                output = self.load_sample(sample)
            else:
                retcode = 1
            process_mock = mock.Mock()
            process_attrs = {
                'communicate.return_value': (output, None),
                'poll.return_value': retcode
            }
            process_mock.configure_mock(**process_attrs)
            return process_mock
        return side_effect

    def __call__(self, func):
        def func_wrapper(obj, mock_popen, mock_platform, mock_socket, *args):
            if self.platform_name == 'Windows':
                getmac.getmac.IS_WINDOWS = True
            getmac.getmac._SYST = self.platform_name
            mock_popen.side_effect = self.create_side_effect(self.cmd, self.sample)
            platform_mock = mock.Mock()
            platform_attrs = {
                'system.return_value': self.platform_name
            }
            platform_mock.configure_mock(**platform_attrs)
            mock_platform.return_value = platform_mock
            socket_mock = mock.Mock()
            mock_socket.return_value = socket_mock
            func(obj)
        return func_wrapper


def mock_helper(platform_name, cmd, sample):
    return MockHelper(platform_name, cmd, sample)


@mock.patch('getmac.getmac.socket.socket')
@mock.patch('getmac.getmac.platform')
@mock.patch('getmac.getmac.Popen')
class TestSamples(unittest.TestCase):
    # Generic samples
    @mock_helper('Linux', 'ifconfig', 'ifconfig.out')
    def test_ifconfig(self):
        mac = getmac.get_mac_address(interface='eth0')
        self.assertEqual('74:d4:35:e9:45:71', mac)

    @mock_helper('Linux', 'ip link', 'ip_link_list.out')
    def test_ip_link_list(self):
        mac = getmac.get_mac_address(interface='eth0')
        self.assertEqual('74:d4:35:e9:45:71', mac)

    # OSX samples
    @mock_helper('Darwin', 'ifconfig', 'OSX/ifconfig.out')
    def test_osx_ifconfig(self):
        mac = getmac.get_mac_address(interface='en0')
        self.assertEqual('2c:f0:ee:2f:c7:de', mac)

    @mock_helper('Darwin', 'arp -a', 'OSX/arp_-a.out')
    def test_osx_arp_a(self):
        mac = getmac.get_mac_address(ip='192.168.1.1')
        self.assertEqual('58:6d:8f:7:c9:94', mac)

    @mock_helper('Darwin', 'arp -an', 'OSX/arp_-an.out')
    def test_osx_arp_an(self):
        mac = getmac.get_mac_address(ip='192.168.1.1')
        self.assertEqual('58:6d:8f:7:c9:94', mac)

    # Windows samples
    @mock_helper('Windows', 'getmac.exe', 'windows_10/getmac.out')
    def test_windows_getmac(self):
        mac = getmac.get_mac_address(interface='Ethernet 2')
        self.assertEqual('74:d4:35:e9:45:71', mac)

    @mock_helper('Windows', 'ipconfig.exe /all', 'windows_10/ipconfig-all.out')
    def test_windows_ipconfig_all(self):
        mac = getmac.get_mac_address(interface='Ethernet 3')
        self.assertEqual('74:d4:35:e9:45:71', mac)

    @mock_helper('Windows', 'wmic.exe nic', 'windows_10/wmic_nic.out')
    def test_windows_wmic_nic(self):
        mac = getmac.get_mac_address(interface='Ethernet 3')
        self.assertEqual('00:ff:17:15:f8:c8', mac)

    # Linux samples
    @mock_helper('Linux', 'arp -a', 'ubuntu_18.04/arp_-a.out')
    def test_linux_arp_a(self):
        mac = getmac.get_mac_address(ip='192.168.16.2')
        self.assertEqual('00:50:56:f1:4c:50', mac)

    @mock_helper('Linux', 'arp -an', 'ubuntu_18.04/arp_-an.out')
    def test_linux_arp_an(self):
        mac = getmac.get_mac_address(ip='192.168.16.2')
        self.assertEqual('00:50:56:f1:4c:50', mac)

    @mock_helper('Linux', 'cat /proc/net/arp', 'ubuntu_18.04/cat_proc-net-arp.out')
    def test_linux_cat_proc_net_arp(self):
        mac = getmac.get_mac_address(ip='192.168.16.2')
        self.assertEqual('00:50:56:f1:4c:50', mac)

    @mock_helper('Linux', 'ifconfig ens33', 'ubuntu_18.04/ifconfig_ens33.out')
    def test_linux_ifconfig_ens33(self):
        mac = getmac.get_mac_address(interface='ens33')
        self.assertEqual('00:0c:29:b5:72:37', mac)

    @mock_helper('Linux', 'ifconfig', 'ubuntu_18.04/ifconfig.out')
    def test_linux_ifconfig(self):
        mac = getmac.get_mac_address(interface='ens33')
        self.assertEqual('00:0c:29:b5:72:37', mac)

    @mock_helper('Linux', 'ip link', 'ubuntu_18.04/ip_link_list.out')
    def test_linux_ip_link_list(self):
        mac = getmac.get_mac_address(interface='ens33')
        self.assertEqual('00:0c:29:b5:72:37', mac)

    @mock_helper('Linux', 'ip link', 'ubuntu_18.04/ip_link.out')
    def test_linux_ip_link(self):
        mac = getmac.get_mac_address(interface='ens33')
        self.assertEqual('00:0c:29:b5:72:37', mac)

    @mock_helper('Linux', 'ip neighbor show 192.168.16.2',
                 'ubuntu_18.04/ip_neighbor_show_192-168-16-2.out')
    def test_linux_ip_neighbor_show_192_168_16_2(self):
        mac = getmac.get_mac_address(ip='192.168.16.2')
        self.assertEqual('00:50:56:f1:4c:50', mac)

    @mock_helper('Linux', 'ip neighbor show', 'ubuntu_18.04/ip_neighbor_show.out')
    def test_linux_ip_neighbor_show(self):
        mac = getmac.get_mac_address(ip='192.168.16.2')
        self.assertEqual('00:50:56:f1:4c:50', mac)

    @mock_helper('Linux', 'netstat -iae', 'ubuntu_18.04/netstat_iae.out')
    def test_linux_netstat_iae(self):
        mac = getmac.get_mac_address(interface='ens33')
        self.assertEqual('00:0c:29:b5:72:37', mac)


class TestGetMacAddress(unittest.TestCase):
    def test_get_mac_address_ip_localhost(self):
        result = getmac.get_mac_address(ip='127.0.0.1')
        self.assertIsNotNone(result)


class TestFailures(unittest.TestCase):
    def test_iface_ip(self):
        pass


class TestInternalMethods(unittest.TestCase):
    pass


class TestThirdPartyPackages(unittest.TestCase):
    pass


if __name__ == '__main__':
    unittest.main()
