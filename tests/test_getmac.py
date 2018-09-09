#!/usr/bin/env python

# http://multivax.com/last_question.html

"""Unit and functional tests for get-mac."""

import unittest
import getmac

getmac.DEBUG = True


# TODO: mock Popen return to be string with typical output of command being tested


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
