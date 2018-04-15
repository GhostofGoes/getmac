#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import sys

import getmac


def main():
    """CLI entrypoint for get-mac."""

    # TODO: default to local interface if no args are specified
    # TODO: argcomplete?
    parser = argparse.ArgumentParser(
        description='Get the MAC address of remote hosts '
                    'or network interfaces using Python.',
        prog='get-mac', add_help=True)
    parser.add_argument('--version', action='version',
                        version='get-mac %s' % getmac.getmac.__version__)
    parser.add_argument('--no-network-requests', action='store_true',
                        help='Disable refreshing of the ARP '
                             'table by making a network request (ping)')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--interface', type=str, default=None,
                       help='Name of a network interface on the system')
    group.add_argument('--ip', type=str, default=None,
                       help='IPv4 address of a remote host')
    group.add_argument('--ip6', type=str, default=None,
                       help='IPv6 address of a remote host')
    group.add_argument('--hostname', type=str, default=None,
                       help='Hostname of a remote host')
    parser.add_argument('--debug', action='store_true',
                        help='For debugging failures')
    args = parser.parse_args()

    if args.debug:
        getmac.getmac.DEBUG = True

    mac = getmac.get_mac_address(interface=args.interface, ip=args.ip,
                                 ip6=args.ip6, hostname=args.hostname,
                                 network_request=args.no_network_requests)
    print("" if mac is None else mac)
    sys.exit(0)


if __name__ == '__main__':
    main()
