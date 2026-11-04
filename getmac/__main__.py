#!/usr/bin/env python3

import argparse
import logging
import sys
import traceback
import warnings
from typing import NoReturn, Union

from . import getmac
from .variables import consts, gvars, settings

ISSUES_URL = "https://github.com/GhostofGoes/getmac/issues"

# Exit codes
EXIT_FOUND = 0
EXIT_NOT_FOUND = 1
EXIT_USAGE = 2  # What argparse uses for invalid arguments
EXIT_ERROR = 3
EXIT_INTERRUPTED = 130  # 128 + SIGINT, what shells use for Ctrl-C


def _seconds(value: str) -> float:
    try:
        seconds = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number of seconds: '{value}'") from None
    if seconds < 0:
        raise argparse.ArgumentTypeError(f"must be 0 or more seconds: '{value}'")
    return seconds


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="getmac",
        description="Get MAC addresses of network interfaces or LAN hosts",
    )
    parser.add_argument("--version", action="version", version=f"getmac {getmac.__version__}")

    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument(
        "-i",
        "--interface",
        type=str,
        default=None,
        help="Name of a network interface on the system",
    )
    group.add_argument(
        "-4",
        "--ip",
        type=str,
        default=None,
        help="IPv4 address of a remote host",
    )
    group.add_argument(
        "-6",
        "--ip6",
        type=str,
        default=None,
        help="IPv6 address of a remote host",
    )
    group.add_argument(
        "-n",
        "--hostname",
        type=str,
        default=None,
        help="Hostname of a remote host",
    )
    group.add_argument(
        "-D",
        "--default-interface",
        action="store_true",
        help="Print the name of the default network interface, instead of a MAC",
    )
    group.add_argument(
        "--list-methods",
        action="store_true",
        help="List the methods for each type of lookup on this platform, in the order "
        "getmac tries them, and whether each one works here. Then exit.",
    )

    parser.add_argument(
        "-N",
        "--no-net",
        "--no-network-requests",
        action="store_true",
        dest="NO_NET",
        help="Do not use arping or send a UDP packet to refresh the ARP table",
    )
    parser.add_argument(
        "--arp-timeout",
        type=_seconds,
        default=None,
        metavar="SECONDS",
        help="After sending the UDP packet to refresh the ARP table, keep checking it for "
        "the host for up to this many seconds (default: 0, check once)",
    )
    parser.add_argument(
        "--command-timeout",
        type=_seconds,
        default=None,
        metavar="SECONDS",
        help="Stop a command that getmac runs (e.g. 'arp' or 'ipconfig.exe') if it takes "
        "longer than this many seconds, and try the next method "
        "(default: 15, 0 to wait for as long as it takes)",
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
        "(e.g. 'linux', 'windows', 'freebsd', etc.). "
        "Any value returned by platform.system() is valid.",
    )
    tshooting.add_argument(
        "--force-method",
        type=str,
        default=None,
        metavar="METHOD",
        help="Force a specific method to be used, e.g. 'IpNeighborShow'. "
        "This will be used regardless of its method type or platform "
        "compatibility, and Method.test() will NOT be checked!",
    )
    tshooting.add_argument(
        "-E",
        "--exclude-method",
        action="append",
        default=None,
        metavar="METHOD",
        help="Don't use this method, e.g. 'ArpFile'. getmac uses the next method "
        "that works instead. Give it more than once to exclude more methods.",
    )

    return parser


def _exclude_methods(parser: argparse.ArgumentParser, names: list[str]) -> None:
    # Check every name before removing any, so a typo doesn't leave METHODS half-changed
    excluded = []
    for name in names:
        method = getmac.get_method_by_name(name.strip())
        if method is None:
            parser.error(f"argument --exclude-method: unknown method '{name}'")
        excluded.append(method)

    for method in excluded:
        if method in getmac.METHODS:  # The same method can be named twice
            getmac.METHODS.remove(method)
            gvars.log.debug(f"Excluding method '{method.__name__}'")


def _list_methods(network_request: bool) -> None:
    """
    Print the methods that would be considered for each type of lookup, the way
    :func:`~getmac.getmac.initialize_method_cache` picks them, and their test results.
    """
    platform = settings.OVERRIDE_PLATFORM.strip().lower() or consts.PLATFORM
    print(f"Platform: {platform}")  # noqa: T201

    for method_type in getmac.METHOD_CACHE:
        type_methods = [
            m
            for m in getmac.METHODS
            if m.method_type == method_type
            or (m.method_type == "ip" and method_type in ("ip4", "ip6"))
        ]
        candidates = [m for m in type_methods if platform in m.platforms] or [
            m for m in type_methods if "other" in m.platforms
        ]

        print(f"\n{method_type}:")  # noqa: T201
        if not candidates:
            print("  (none)")  # noqa: T201
            continue

        chosen = False
        for method_class in candidates:
            if method_class.network_request and not network_request:
                status = "skipped (sends packets, and --no-net is set)"
            else:
                try:
                    works = method_class().test()
                except Exception:
                    works = False

                if not works:
                    status = "doesn't work here (test() failed)"
                elif chosen:
                    status = "fallback"
                else:
                    status = "primary"
                    chosen = True
            print(f"  {method_class.__name__:<28} {status}")  # noqa: T201


def _show_warning(message: Union[Warning, str], *_args: object, **_kwargs: object) -> None:
    """Print warnings like the other messages, without a file path and a line of code."""
    print(f"getmac: warning: {message}", file=sys.stderr)  # noqa: T201


def _error(message: str) -> NoReturn:
    print(f"getmac: error: {message}", file=sys.stderr)  # noqa: T201
    sys.exit(EXIT_ERROR)


def main() -> None:
    """
    Run the ``getmac`` command. Exits with :data:`EXIT_FOUND` (``0``) if the MAC (or
    interface) was found and printed, :data:`EXIT_NOT_FOUND` (``1``) if it wasn't,
    :data:`EXIT_USAGE` (``2``) if the arguments are invalid, :data:`EXIT_ERROR` (``3``)
    if the lookup failed with an error, and :data:`EXIT_INTERRUPTED` (``130``) on Ctrl-C.
    """
    try:
        with warnings.catch_warnings():
            warnings.showwarning = _show_warning
            _main()
    except KeyboardInterrupt:
        sys.exit(EXIT_INTERRUPTED)


def _main() -> NoReturn:
    parser = build_parser()
    args = parser.parse_args()

    if args.debug or args.verbose:
        logging.basicConfig(
            format="%(levelname)-8s %(message)s",
            level=logging.DEBUG,
            stream=sys.stderr,
        )

    if args.debug:
        settings.DEBUG = args.debug

    if args.override_port:
        port = int(args.override_port)
        gvars.log.debug(f"Using UDP port {port} (overriding the default port {settings.PORT})")
        settings.PORT = port

    if args.arp_timeout is not None:
        settings.ARP_TIMEOUT = args.arp_timeout

    if args.command_timeout is not None:
        settings.COMMAND_TIMEOUT = args.command_timeout

    if args.override_platform:
        settings.OVERRIDE_PLATFORM = args.override_platform.strip().lower()

    if args.force_method:
        settings.FORCE_METHOD = args.force_method.strip().lower()

    if args.exclude_method:
        _exclude_methods(parser, args.exclude_method)

    if args.list_methods:
        _list_methods(network_request=not args.NO_NET)
        sys.exit(EXIT_FOUND)

    try:
        if args.default_interface:
            result = getmac.get_default_interface()
        else:
            result = getmac.get_mac_address(
                interface=args.interface,
                ip=args.ip,
                ip6=args.ip6,
                hostname=args.hostname,
                network_request=not args.NO_NET,
            )
    except RuntimeError as ex:
        # No methods for the platform, or none of them work. The message says why.
        if args.debug:
            traceback.print_exc()
        _error(str(ex))
    except Exception as ex:
        # E.g. a method forced with --force-method raised. Its exceptions aren't caught.
        if args.debug:
            traceback.print_exc()
        _error(
            f"unexpected {type(ex).__name__}: {ex}\n"
            f"If this looks like a bug, please report it at {ISSUES_URL}, "
            "with the output of the same command with '-v -dddd' added"
        )

    if result:
        print(result)  # noqa: T201
        sys.exit(EXIT_FOUND)

    sys.exit(EXIT_NOT_FOUND)


if __name__ == "__main__":
    main()
