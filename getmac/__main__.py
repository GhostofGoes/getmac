#!/usr/bin/env python3

import argparse
import logging
import sys

from . import getmac
from .variables import settings, gvars


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="getmac",
        description="Get MAC addresses of network interfaces or LAN hosts",
    )
    parser.add_argument(
        "--version", action="version", version=f"getmac {getmac.__version__}"
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

    parser.add_argument(
        "-N",
        "--no-net",
        "--no-network-requests",
        action="store_true",
        dest="NO_NET",
        help="Do not use arping or send a UDP packet to refresh the ARP table",
    )

    tshooting = parser.add_argument_group("troubleshooting")
    tshooting.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable logging messages (by default, only the MAC is printed to the terminal)",
    )
    tshooting.add_argument(
        "-d",
        "--debug",
        action="count",
        help="Enable debugging output. Add 'd' characters to "
        "increase verbosity of output, e.g. '-dd' to set DEBUG=2.",
    )
    tshooting.add_argument(
        "--override-port",
        type=int,
        metavar="PORT",
        help="Override the default UDP port used to refresh the ARP table "
        "if network requests are enabled and arping is unavailable",
    )
    tshooting.add_argument(
        "--override-platform",
        type=str,
        default=None,
        metavar="PLATFORM",
        help="Override the platform detection with the given value "
        "(e.g. 'linux', 'windows', 'freebsd', etc.'). "
        "Any values returned by platform.system() are valid.",
    )
    tshooting.add_argument(
        "--force-method",
        type=str,
        default=None,
        metavar="METHOD",
        help="Force a specific method to be used, e.g. 'IpNeighborShow'. "
        "This will be used regardless of it's method type or platform "
        "compatibility, and Method.test() will NOT be checked!",
    )

    args = parser.parse_args()

    if args.debug or args.verbose:
        logging.basicConfig(
            format="%(levelname)-8s %(message)s", level=logging.DEBUG, stream=sys.stderr
        )

    if args.debug:
        settings.DEBUG = args.debug

    if args.override_port:
        port = int(args.override_port)
        gvars.log.debug(
            "Using UDP port %d (overriding the default port %d)", port, settings.PORT
        )
        settings.PORT = port

    if args.override_platform:
        settings.OVERRIDE_PLATFORM = args.override_platform.strip().lower()

    if args.force_method:
        settings.FORCE_METHOD = args.force_method.strip().lower()

    mac = getmac.get_mac_address(
        interface=args.interface,
        ip=args.ip,
        ip6=args.ip6,
        hostname=args.hostname,
        network_request=not args.NO_NET,
    )

    if mac is not None:
        print(mac)  # noqa: T201
        sys.exit(0)  # Exit success!
    else:
        sys.exit(1)  # Exit with error since it failed to find a MAC


if __name__ == "__main__":
    main()
