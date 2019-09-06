#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import argparse
import logging
import sys

from . import getmac


def main():
    parser = argparse.ArgumentParser(
        "getmac",
        description="Get the MAC address of system network "
        "interfaces or remote hosts on the LAN",
    )
    parser.add_argument(
        "--version", action="version", version="getmac %s" % getmac.__version__
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable output messages"
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="count",
        help="Enable debugging output. Add characters to "
        "increase verbosity of output, e.g. '-dd'.",
    )
    parser.add_argument(
        "-N",
        "--no-net",
        "--no-network-requests",
        action="store_true",
        dest="NO_NET",
        help="Do not send a UDP packet to refresh the ARP table",
    )

    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument(
        "-i",
        "--interface",
        type=str,
        default=None,
        help="Name of a network interface on the system",
    )
    group.add_argument(
        "-4", "--ip", type=str, default=None, help="IPv4 address of a remote host"
    )
    group.add_argument(
        "-6", "--ip6", type=str, default=None, help="IPv6 address of a remote host"
    )
    group.add_argument(
        "-n", "--hostname", type=str, default=None, help="Hostname of a remote host"
    )

    args = parser.parse_args()

    if args.debug or args.verbose:
        logging.basicConfig(
            format="%(levelname)-8s %(message)s", level=logging.DEBUG, stream=sys.stderr
        )
    if args.debug:
        getmac.DEBUG = args.debug

    mac = getmac.get_mac_address(
        interface=args.interface,
        ip=args.ip,
        ip6=args.ip6,
        hostname=args.hostname,
        network_request=not args.NO_NET,
    )

    if mac is not None:
        print(mac)  # noqa: T001
        sys.exit(0)  # Exit success!
    else:
        sys.exit(1)  # Exit with error since it failed to find a MAC


if __name__ == "__main__":
    main()
