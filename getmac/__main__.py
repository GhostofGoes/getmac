#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys

from . import getmac


def main():
    """CLI entrypoint for get-mac."""

    # TODO: default to local interface if no args are specified
    # TODO: argcomplete?
    # TODO: make a note about python 2.6 and terminal interface
    import argparse
    parser = argparse.ArgumentParser(
        description='Get the MAC address of remote hosts '
                    'or network interfaces using Python.',
        prog='get-mac', add_help=True)
    parser.add_argument('--version', action='version',
                        version='get-mac %s' % getmac.__version__)
    parser.add_argument('--no-network-requests', action='store_true',
                        help='Disable refreshing of the ARP '
                             'table by making a network request (ping)')
    group = parser.add_mutually_exclusive_group(required=False)
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
        getmac.DEBUG = True

    mac = getmac.get_mac_address(interface=args.interface, ip=args.ip,
                                 ip6=args.ip6, hostname=args.hostname,
                                 network_request=not args.no_network_requests)

    if mac is not None:
        print(mac)
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == '__main__':
    main()
