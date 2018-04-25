#!/usr/bin/env python
# -*- coding: utf-8 -*-


# http://multivax.com/last_question.html

"""Unit and functional tests for get-mac."""

import unittest
import getmac

getmac.DEBUG = True


def main():
    print(getmac.get_mac_address(interface="eth0"))
    print(getmac.get_mac_address(interface="Ethernet 3"))
    print(getmac.get_mac_address(ip="10.0.0.1"))
    print(getmac.get_mac_address(hostname="localhost"))
    print(getmac.get_mac_address(ip="10.0.0.1", network_request=True))


if __name__ == "__main__":
    main()
