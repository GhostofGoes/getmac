#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Unit and functional tests for get-mac."""

import get_mac
get_mac.DEBUG = True


def main():
    print(get_mac.get_mac_address(interface="eth1"))
    print(get_mac.get_mac_address(interface="Ethernet 3"))
    print(get_mac.get_mac_address(ip="10.0.0.1"))
    print(get_mac.get_mac_address(hostname="localhost"))
    print(get_mac.get_mac_address(ip="10.0.0.1", arp_request=True))


if __name__ == "__main__":
    main()
