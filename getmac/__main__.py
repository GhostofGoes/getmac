#!/usr/bin/env python3

import argparse
import difflib
import logging
import math
import re
import sys
import textwrap
import traceback
import warnings
from collections.abc import Iterable
from typing import NoReturn, Optional, Union

from . import getmac
from .variables import consts, gvars, settings

DOCS_URL = "https://ghostofgoes.github.io/getmac/cli.html"
ISSUES_URL = "https://github.com/GhostofGoes/getmac/issues"

EPILOG = f"""\
examples:
  getmac                    MAC of the default interface
  getmac -i eth0            MAC of an interface
  getmac -4 192.168.0.1     MAC of a host on the LAN
  getmac -n home.router     MAC of a host on the LAN, by name
  getmac -D                 name of the default interface

exit codes:
  0    found, and printed to stdout
  1    not found
  2    invalid arguments
  3    error (printed to stderr)
  130  stopped with Ctrl-C

docs:   {DOCS_URL}
issues: {ISSUES_URL}
        (include the output of the command with '-v -dddd' added)
"""

# Exit codes
EXIT_FOUND = 0
EXIT_NOT_FOUND = 1
EXIT_USAGE = 2  # What argparse uses for invalid arguments
EXIT_ERROR = 3
EXIT_INTERRUPTED = 130  # 128 + SIGINT, what shells use for Ctrl-C


# Options whose value can be a negative number, which argparse otherwise takes
# for an option (since -4 and -6 are options), see _join_negative_values()
NUMBER_OPTIONS = ("--arp-timeout", "--command-timeout", "--override-port")
NEGATIVE_NUMBER = re.compile(r"-(\d+\.?\d*(e\d+)?|\.\d+|inf(inity)?|nan)", re.IGNORECASE)


def _seconds(value: str) -> float:
    try:
        seconds = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number of seconds: '{value}'") from None
    if not math.isfinite(seconds):  # nan and inf
        raise argparse.ArgumentTypeError(f"not a number of seconds: '{value}'")
    if seconds < 0:
        raise argparse.ArgumentTypeError(f"must be 0 or more seconds: '{value}'")
    return seconds


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a port number: '{value}'") from None
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"must be a port from 1 to 65535: '{value}'")
    return port


def _join_negative_values(argv: list[str]) -> list[str]:
    """
    Turn e.g. ``--arp-timeout -1`` into ``--arp-timeout=-1``. Because ``-4`` and ``-6``
    are options, argparse takes ``-1`` for an option too, and says the option is
    "expected one argument" instead of saying what's wrong with the value.
    """
    joined: list[str] = []
    args = iter(argv)
    for arg in args:
        if arg == "--":
            joined.append(arg)
            joined.extend(args)
            break
        if arg in NUMBER_OPTIONS:
            value = next(args, None)
            if value is not None and NEGATIVE_NUMBER.fullmatch(value):
                joined.append(f"{arg}={value}")
                continue
            joined.append(arg)
            if value is not None:
                joined.append(value)
            continue
        joined.append(arg)
    return joined


def _method_names() -> list[str]:
    return [method.__name__ for method in getmac.METHODS]


def _platform_names() -> set[str]:
    """Platforms that ``--override-platform`` accepts: any that a method is for."""
    return set(getmac.Method.VALID_PLATFORM_NAMES).union(
        *(method.platforms for method in getmac.METHODS)
    )


class _HelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Keeps the description and examples as written, and doesn't split '--list-methods'."""

    def _split_lines(self, text: str, width: int) -> list[str]:
        text = self._whitespace_matcher.sub(" ", text).strip()
        return textwrap.wrap(text, width, break_on_hyphens=False)


def _closest(name: str, names: Iterable[str]) -> Optional[str]:
    """The one of ``names`` that's closest to ``name`` (ignoring case), if any are close."""
    lowered = {n.lower(): n for n in names}
    matches = difflib.get_close_matches(name.strip().lower(), lowered, n=1)
    return lowered[matches[0]] if matches else None


def _did_you_mean(name: str, names: Iterable[str]) -> str:
    closest = _closest(name, names)
    return f" (did you mean '{closest}'?)" if closest else ""


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        """Suggest the option that was meant, e.g. '--interface' for '--interfaces'."""
        prefix = "unrecognized arguments: "
        if message.startswith(prefix):
            options = [
                opt
                for action in self._actions
                for opt in action.option_strings
                if opt.startswith("--")
            ]
            suggestions = []
            for arg in message[len(prefix) :].split():
                closest = _closest(arg.split("=", 1)[0], options) if arg.startswith("--") else None
                if closest:
                    suggestions.append((arg, closest))
            if len(suggestions) == 1:
                message += f" (did you mean '{suggestions[0][1]}'?)"
            elif suggestions:
                message += (
                    " (did you mean "
                    + ", ".join(f"'{closest}' for '{arg}'" for arg, closest in suggestions)
                    + "?)"
                )
        super().error(message)


def build_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        prog="getmac",
        # Don't accept the start of an option, e.g. "--int" for "--interface". If scripts
        # use them, adding an option with the same start (e.g. "--interval") breaks them.
        allow_abbrev=False,
        description="Get MAC addresses of network interfaces or LAN hosts.\n"
        "With no arguments, prints the MAC of the default interface.",
        epilog=EPILOG,
        formatter_class=_HelpFormatter,
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
        help="Print log messages to stderr, e.g. which methods were tried "
        "(by default, only the result is printed)",
    )
    tshooting.add_argument(
        "-d",
        "--debug",
        action="count",
        help="Print more detail about each method getmac tries, and implies -v. "
        "Give it more than once for more detail, up to -dddd (every command and its output).",
    )
    tshooting.add_argument(
        "--override-port",
        type=_port,
        metavar="PORT",
        help="Send the UDP packet that refreshes the ARP table to this port "
        "(default: 55555). Only used if arping isn't available and -N isn't set.",
    )
    tshooting.add_argument(
        "--override-platform",
        type=str,
        default=None,
        metavar="PLATFORM",
        help="Use the methods for this platform instead of the one getmac detects: "
        + ", ".join(sorted(getmac.Method.VALID_PLATFORM_NAMES)),
    )
    tshooting.add_argument(
        "--force-method",
        type=str,
        default=None,
        metavar="METHOD",
        help="Use only this method, e.g. 'IpNeighborShow', even if it isn't for this "
        "platform or type of lookup, and without checking first that it works here "
        "(see --list-methods for the names)",
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
            parser.error(
                f"argument --exclude-method: unknown method '{name}'"
                + _did_you_mean(name, _method_names())
            )
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
    args = parser.parse_args(_join_negative_values(sys.argv[1:]))

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
        platform = args.override_platform.strip().lower()
        if platform not in _platform_names():
            parser.error(
                f"argument --override-platform: unknown platform '{args.override_platform}'"
                + (
                    _did_you_mean(platform, _platform_names())
                    or f" (choose from {', '.join(sorted(_platform_names()))})"
                )
            )
        settings.OVERRIDE_PLATFORM = platform

    forced = None
    if args.force_method:
        forced = getmac.get_method_by_name(args.force_method.strip())
        if forced is None:
            parser.error(
                f"argument --force-method: unknown method '{args.force_method}'"
                + (
                    _did_you_mean(args.force_method, _method_names())
                    or " (--list-methods shows the methods for this platform)"
                )
            )
        settings.FORCE_METHOD = args.force_method.strip().lower()

    if args.exclude_method:
        _exclude_methods(parser, args.exclude_method)

    if forced is not None and forced not in getmac.METHODS:
        parser.error(
            f"argument --force-method: '{args.force_method}' is excluded with --exclude-method"
        )

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
