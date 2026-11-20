#!/usr/bin/env python3

import argparse
import difflib
import json
import logging
import math
import re
import sys
import textwrap
import traceback
import warnings
from collections.abc import Iterable
from typing import Any, Final, NoReturn, Optional, Union

from . import getmac
from .variables import consts, gvars, settings

DOCS_URL: Final[str] = "https://ghostofgoes.github.io/getmac/cli.html"
ISSUES_URL: Final[str] = "https://github.com/GhostofGoes/getmac/issues"

EPILOG: Final[str] = f"""\
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
EXIT_FOUND: Final[int] = 0
EXIT_NOT_FOUND: Final[int] = 1
EXIT_USAGE: Final[int] = 2  # argparse uses this code for arguments that are not valid
EXIT_ERROR: Final[int] = 3
EXIT_INTERRUPTED: Final[int] = 130  # 128 + SIGINT. Shells use this code for Ctrl-C.


# These options take a number. If the number is negative (for example "-1"), argparse reads
# it as an option, because -4 and -6 are options. _join_negative_values() prevents that.
NUMBER_OPTIONS: Final[tuple[str, ...]] = ("--arp-timeout", "--command-timeout", "--override-port")
NEGATIVE_NUMBER: Final[re.Pattern[str]] = re.compile(
    r"-(\d+\.?\d*(e\d+)?|\.\d+|inf(inity)?|nan)", re.IGNORECASE
)


def _seconds(value: str) -> float:
    try:
        seconds = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number of seconds: '{value}'") from None
    if not math.isfinite(seconds):  # The value is nan or inf
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
    Join a number option and its negative value. For example, ``--arp-timeout -1`` becomes
    ``--arp-timeout=-1``. Because ``-4`` and ``-6`` are options, argparse reads ``-1`` as an
    option too. Its error is then "expected one argument", which does not tell the user
    what is wrong with the value.
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


class _HelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Keep the description and the examples as written, and do not split '--list-methods'."""

    def _split_lines(self, text: str, width: int) -> list[str]:
        text = self._whitespace_matcher.sub(" ", text).strip()
        return textwrap.wrap(text, width, break_on_hyphens=False)


def _closest(name: str, names: Iterable[str]) -> Optional[str]:
    """
    Return the name in ``names`` that is closest to ``name``. The comparison ignores case.
    If no name is close, return :obj:`None`.
    """
    lowered = {n.lower(): n for n in names}
    matches = difflib.get_close_matches(name.strip().lower(), lowered, n=1)
    return lowered[matches[0]] if matches else None


def _did_you_mean(name: str, names: Iterable[str]) -> str:
    closest = _closest(name, names)
    return f" (did you mean '{closest}'?)" if closest else ""


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        """Suggest the closest option, for example '--interface' for '--interfaces'."""
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
        # Do not accept the start of an option, for example "--int" for "--interface". A new
        # option with the same start (for example "--interval") breaks the scripts that use it.
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
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the result as JSON, with the method that found it and the platform. "
        "Also works with -D and --list-methods.",
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
                + _did_you_mean(name, getmac.get_method_names())
            )
        excluded.append(method)

    for method in excluded:
        if method in getmac.METHODS:  # The same method can be named twice
            getmac.METHODS.remove(method)
            gvars.log.debug(f"Excluding method '{method.__name__}'")


# The --list-methods statuses, and the text that getmac prints for each one without --json
METHOD_STATUSES: Final[dict[str, str]] = {
    "primary": "primary",
    "fallback": "fallback",
    "failed": "doesn't work here (test() failed)",
    "skipped": "skipped (sends packets, and --no-net is set)",
}


def _platform() -> str:
    return settings.OVERRIDE_PLATFORM.strip().lower() or consts.PLATFORM


def _method_statuses(network_request: bool) -> dict[str, list[tuple[str, str]]]:
    """
    Return the methods that getmac considers for each type of lookup, and the status of
    each one (a key of :data:`METHOD_STATUSES`). This function selects the methods the same
    way that :func:`~getmac.getmac.initialize_method_cache` does.
    """
    platform = _platform()
    statuses: dict[str, list[tuple[str, str]]] = {}

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

        statuses[method_type] = []
        chosen = False
        for method_class in candidates:
            if method_class.network_request and not network_request:
                status = "skipped"
            else:
                try:
                    works = method_class().test()
                except Exception:
                    works = False

                if not works:
                    status = "failed"
                elif chosen:
                    status = "fallback"
                else:
                    status = "primary"
                    chosen = True
            statuses[method_type].append((method_class.__name__, status))

    return statuses


def _list_methods(network_request: bool, as_json: bool) -> None:
    statuses = _method_statuses(network_request)

    if as_json:
        _print_json(
            {
                "platform": _platform(),
                "methods": {
                    method_type: [{"name": name, "status": status} for name, status in methods]
                    for method_type, methods in statuses.items()
                },
            }
        )
        return

    print(f"Platform: {_platform()}")  # noqa: T201
    for method_type, methods in statuses.items():
        print(f"\n{method_type}:")  # noqa: T201
        if not methods:
            print("  (none)")  # noqa: T201
        for name, status in methods:
            print(f"  {name:<28} {METHOD_STATUSES[status]}")  # noqa: T201


def _print_json(data: dict[str, Any]) -> None:
    # Indent the JSON for people. Print one line for scripts, which can then read the
    # output line by line.
    print(json.dumps(data, indent=2 if sys.stdout.isatty() else None))  # noqa: T201


def _show_warning(message: Union[Warning, str], *_args: object, **_kwargs: object) -> None:
    """Print a warning like the other messages, without a file path and a line of code."""
    print(f"getmac: warning: {message}", file=sys.stderr)  # noqa: T201


def _error(message: str) -> NoReturn:
    print(f"getmac: error: {message}", file=sys.stderr)  # noqa: T201
    sys.exit(EXIT_ERROR)


def main() -> None:
    """
    Run the ``getmac`` command, then exit with one of these codes:

    - :data:`EXIT_FOUND` (``0``): getmac found the MAC (or the interface) and printed it.
    - :data:`EXIT_NOT_FOUND` (``1``): getmac did not find it.
    - :data:`EXIT_USAGE` (``2``): the arguments are not valid.
    - :data:`EXIT_ERROR` (``3``): the lookup failed with an error.
    - :data:`EXIT_INTERRUPTED` (``130``): the user pressed Ctrl-C.
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
        if platform not in getmac.get_platform_names():
            parser.error(
                f"argument --override-platform: unknown platform '{args.override_platform}'"
                + (
                    _did_you_mean(platform, getmac.get_platform_names())
                    or f" (choose from {', '.join(sorted(getmac.get_platform_names()))})"
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
                    _did_you_mean(args.force_method, getmac.get_method_names())
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
        _list_methods(network_request=not args.NO_NET, as_json=args.json)
        sys.exit(EXIT_FOUND)

    gvars.LAST_METHOD = ""

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
        # There are no methods for the platform, or none of them work. The message gives
        # the cause.
        if args.debug:
            traceback.print_exc()
        _error(str(ex))
    except Exception as ex:
        # For example, a method forced with --force-method raised an exception. getmac does
        # not catch the exceptions of a forced method.
        if args.debug:
            traceback.print_exc()
        _error(
            f"unexpected {type(ex).__name__}: {ex}\n"
            f"If this looks like a bug, please report it at {ISSUES_URL}, "
            "with the output of the same command with '-v -dddd' added"
        )

    if args.json:
        _print_json(_result_json(args, result or None))
    elif result:
        print(result)  # noqa: T201

    sys.exit(EXIT_FOUND if result else EXIT_NOT_FOUND)


def _result_json(args: argparse.Namespace, result: Optional[str]) -> dict[str, Any]:
    """
    Return the data that ``--json`` prints for a lookup. If getmac found nothing, ``result``
    is :obj:`None`.
    """
    method = (gvars.LAST_METHOD or None) if result else None

    if args.default_interface:
        return {"interface": result, "method": method, "platform": _platform()}

    lookup, target = "default", None
    for name in ("interface", "ip", "ip6", "hostname"):
        if getattr(args, name) is not None:
            lookup, target = name, getattr(args, name)

    return {
        "mac": result,
        "lookup": lookup,
        "target": target,
        "method": method,
        "platform": _platform(),
    }


if __name__ == "__main__":
    main()
