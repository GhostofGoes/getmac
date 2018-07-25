#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys

from . import getmac


def main():
    """CLI entrypoint. Invoked using `get-mac` or `python -m getmac`."""

    try:
        import argparse
    except ImportError:
        print("Python 2.6 is not supported for the terminal interface")
        sys.exit(1)

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
    group.add_argument('-i', '--interface', type=str, default=None,
                       help='Name of a network interface on the system')
    group.add_argument('-4', '--ip', type=str, default=None,
                       help='IPv4 address of a remote host')
    group.add_argument('-6', '--ip6', type=str, default=None,
                       help='IPv6 address of a remote host')
    group.add_argument('-n', '--hostname', type=str, default=None,
                       help='Hostname of a remote host')
    parser.add_argument('-d', '--debug', action='store_true',
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
