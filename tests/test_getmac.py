#!/usr/bin/env python

# http://multivax.com/last_question.html

"""Unit and functional tests for get-mac."""

import unittest
import getmac
from os import path
from unittest import mock

getmac.DEBUG = True


class TestSamples(unittest.TestCase):
    def load_sample(self, filename):
        filename = path.realpath('%s/../samples/%s' % (path.dirname(__file__), filename))
        content = ''
        with open(filename, 'r') as f:
            content = f.read()
        return content

    def create_side_effect(self, cmd, sample):
        def side_effect(params, *args, **kwargs):
            output = None
            retcode = 0
            params = ' '.join(params)
            if cmd in params:
                output = self.load_sample(sample)
            else:
                retcode = 1
            process_mock = mock.Mock()
            attrs = {
                'communicate.return_value': (output, None),
                'poll.return_value': retcode
            }
            process_mock.configure_mock(**attrs)
            return process_mock
        return side_effect

    def test_ifconfig(self, mock_popen):
        mock_popen.side_effect = self.create_side_effect('ifconfig', 'ifconfig.out')
        mac = getmac.get_mac_address(interface='eth0')
        self.assertEqual('74:d4:35:e9:45:71', mac)
    
    def test_ip_link_list(self, mock_popen):
        mock_popen.side_effect = self.create_side_effect('ip link', 'ip_link_list.out')
        mac = getmac.get_mac_address(interface='eth0')
        self.assertEqual('74:d4:35:e9:45:71', mac)

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
