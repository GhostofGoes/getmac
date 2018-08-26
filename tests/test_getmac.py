#!/usr/bin/env python

# http://multivax.com/last_question.html

"""Unit and functional tests for get-mac."""

import unittest
import getmac

getmac.DEBUG = True

# TODO: mock the results of Popen to be a static string
#       with the typical output of the command being tested
class TestFailures(unittest.TestCase):
    def test_iface_ip(self):
        pass


if __name__ == "__main__":
    unittest.main()
