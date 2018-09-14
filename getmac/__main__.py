#!/usr/bin/env python
import sys
from . import getmac


def main():
    try:
        import argparse
    except ImportError:
        print("You must install argparse on Python 2.6 and below ('pip install argparse')")
        sys.exit(1)

    parser = argparse.ArgumentParser('get-mac', description='Get the MAC address of system network interfaces or remote hosts on the LAN')
    parser.add_argument('--version', action='version', version='get-mac %s' % getmac.__version__)
    parser.add_argument('-d', '--debug', action='count', help='Enable debugging output. Add characters to increase verbosity of output, e.g. \'-dd\'.')
    parser.add_argument('--no-network-requests', action='store_true', help='Do not send a UDP packet to refresh the ARP table')

    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('-i', '--interface', type=str, default=None, help='Name of a network interface on the system')
    group.add_argument('-4', '--ip', type=str, default=None, help='IPv4 address of a remote host')
    group.add_argument('-6', '--ip6', type=str, default=None, help='IPv6 address of a remote host')
    group.add_argument('-n', '--hostname', type=str, default=None, help='Hostname of a remote host')

    args = parser.parse_args()

    if args.debug:
        getmac.DEBUG = args.debug

    mac = getmac.get_mac_address(
        interface=args.interface, ip=args.ip,
        ip6=args.ip6, hostname=args.hostname,
        network_request=not args.no_network_requests)

    if mac is not None:
        print(mac)
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == '__main__':
    main()
