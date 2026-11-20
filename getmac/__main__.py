#!/usr/bin/env python3

import argparse
import contextlib
import difflib
import json
import logging
import math
import os
import re
import signal
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
  0    getmac found the result and printed it to stdout
  1    getmac did not find the result
  2    the arguments are not valid
  3    an error occurred (getmac printed it to stderr)
  130  you stopped getmac with Ctrl-C

docs:   {DOCS_URL}
issues: {ISSUES_URL}
        (Add '-v -dddd' to the command, and include its output in the report.)
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
    r"-((\d+\.?\d*|\.\d+)(e[+-]?\d+)?|inf(inity)?|nan)", re.IGNORECASE
)


def _seconds(value: str) -> float:
    try:
        seconds = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{value}' is not a number of seconds.") from None
    if not math.isfinite(seconds):
        # "inf" and "nan" are numbers to float(), but can't be waited for
        raise argparse.ArgumentTypeError(
            f"'{value}' is not a number of seconds that getmac can wait. Use 0 for no timeout."
        )
    if seconds < 0:
        raise argparse.ArgumentTypeError(
            f"'{value}' is less than 0. The number of seconds must be 0 or more."
        )
    return seconds


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{value}' is not a port number.") from None
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"'{value}' is not a port from 1 to 65535.")
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
    return f" Did you mean '{closest}'?" if closest else ""


def _one_of(names: list[str]) -> str:
    """Quote the names and join them, for example ``'a', 'b' or 'c'``."""
    quoted = [f"'{name}'" for name in names]
    if len(quoted) == 1:
        return quoted[0]
    return ", ".join(quoted[:-1]) + " or " + quoted[-1]


class _ArgumentParser(argparse.ArgumentParser):
    def _suggest(self, arg: str) -> list[str]:
        """
        Return the options that the user can mean with ``arg``, an option that does not
        exist. These are the options that start with ``arg`` (for example '--interface'
        for '--int'), or if there are none, the option with the closest spelling.
        """
        name = arg.split("=", 1)[0]
        long_options = [
            [opt for opt in action.option_strings if opt.startswith("--")]
            for action in self._actions
        ]
        # One option for each action, because '--no-net' and '--no-network-requests' are
        # the same option
        starts = [
            next(opt for opt in options if opt.startswith(name))
            for options in long_options
            if any(opt.startswith(name) for opt in options)
        ]
        if starts:
            return starts
        closest = _closest(name, [opt for options in long_options for opt in options])
        return [closest] if closest else []

    def error(self, message: str) -> NoReturn:
        """Suggest options for an unknown option, for example '--interface' for '--int'."""
        prefix = "unrecognized arguments: "
        if message.startswith(prefix):
            suggestions = [
                (arg, self._suggest(arg))
                for arg in message[len(prefix) :].split()
                if arg.startswith("--")
            ]
            suggestions = [(arg, options) for arg, options in suggestions if options]
            if len(suggestions) == 1:
                message += f". Did you mean {_one_of(suggestions[0][1])}?"
            elif suggestions:
                message += (
                    ". Did you mean "
                    + ", ".join(f"{_one_of(options)} for '{arg}'" for arg, options in suggestions)
                    + "?"
                )
        super().error(message)


def build_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        prog="getmac",
        # Do not accept the start of an option, for example "--int" for "--interface". A new
        # option with the same start (for example "--interval") breaks the scripts that use it.
        allow_abbrev=False,
        description="Get the MAC address of a network interface or of a host on the LAN.\n"
        "With no arguments, getmac prints the MAC of the default interface.",
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
        help="Print the name of the default network interface, and not a MAC",
    )
    group.add_argument(
        "--list-methods",
        action="store_true",
        help="List the methods for each type of lookup on this platform, in the order "
        "that getmac tries them. Show if each method works here. Then exit.",
    )

    parser.add_argument(
        "-N",
        "--no-net",
        "--no-network-requests",
        action="store_true",
        dest="NO_NET",
        help="Do not use arping, and do not send a UDP packet, to refresh the ARP table",
    )
    parser.add_argument(
        "--arp-timeout",
        type=_seconds,
        default=None,
        metavar="SECONDS",
        help="After getmac sends the UDP packet to refresh the ARP table, look for the host "
        "in the table for up to this many seconds (default: 0, look one time)",
    )
    parser.add_argument(
        "--command-timeout",
        type=_seconds,
        default=None,
        metavar="SECONDS",
        help="If a command that getmac runs (for example 'arp' or 'ipconfig.exe') takes "
        "longer than this many seconds, stop it and try the next method (default: 15). "
        "0 means that getmac waits until the command ends.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the result as JSON, with the method that found it and the platform. "
        "This option also works with -D and --list-methods.",
    )

    tshooting = parser.add_argument_group("troubleshooting")
    tshooting.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print log messages to stderr, for example the methods that getmac tried "
        "(by default, getmac prints only the result)",
    )
    tshooting.add_argument(
        "-d",
        "--debug",
        action="count",
        help="Print more detail about each method that getmac tries. This option includes "
        "-v. Use it more than one time for more detail, up to -dddd (each command and its "
        "output).",
    )
    tshooting.add_argument(
        "--override-port",
        type=_port,
        metavar="PORT",
        help="Send the UDP packet that refreshes the ARP table to this port "
        "(default: 55555). getmac uses the port only if arping is not available and -N "
        "is not set.",
    )
    tshooting.add_argument(
        "--override-platform",
        type=str,
        default=None,
        metavar="PLATFORM",
        help="Use the methods for this platform, and not the methods for the platform that "
        "getmac detects: " + ", ".join(sorted(getmac.Method.VALID_PLATFORM_NAMES)),
    )
    tshooting.add_argument(
        "--force-method",
        type=str,
        default=None,
        metavar="METHOD",
        help="Use only this method, for example 'IpNeighborShow'. getmac uses it even if it "
        "is not for this platform or this type of lookup, and does not test it first. "
        "See --list-methods for the names.",
    )
    tshooting.add_argument(
        "-E",
        "--exclude-method",
        action="append",
        default=None,
        metavar="METHOD",
        help="Do not use this method, for example 'ArpFile'. getmac uses the next method "
        "that works. Use this option more than one time to exclude more methods.",
    )

    return parser


def _exclude_methods(parser: argparse.ArgumentParser, names: list[str]) -> None:
    # Check every name before removing any, so a typo doesn't leave METHODS half-changed
    excluded = []
    for name in names:
        method = getmac.get_method_by_name(name.strip())
        if method is None:
            parser.error(
                f"argument --exclude-method: '{name}' is not the name of a method."
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

    _print(f"Platform: {_platform()}")
    for method_type, methods in statuses.items():
        _print(f"\n{method_type}:")
        if not methods:
            _print("  (none)")
        for name, status in methods:
            _print(f"  {name:<28} {METHOD_STATUSES[status]}")


def _print_json(data: dict[str, Any]) -> None:
    # Indent the JSON for people. Print one line for scripts, which can then read the
    # output line by line.
    _print(json.dumps(data, indent=2 if sys.stdout.isatty() else None))


def _show_warning(message: Union[Warning, str], *_args: object, **_kwargs: object) -> None:
    """Print a warning like the other messages, without a file path and a line of code."""
    print(f"getmac: warning: {message}", file=sys.stderr)  # noqa: T201


def _error(message: str) -> NoReturn:
    print(f"getmac: error: {message}", file=sys.stderr)  # noqa: T201
    sys.exit(EXIT_ERROR)


def _print(text: str) -> None:
    """
    Print ``text`` to stdout. If stdout cannot be written, exit with :data:`EXIT_ERROR`.
    If the reader of a pipe closed it (for example ``getmac | head -1``), there is no
    error message.
    """
    try:
        print(text)  # noqa: T201
        # Flush now. If not, a write error occurs when Python exits, and it is a traceback.
        sys.stdout.flush()
    except OSError as ex:
        _discard_stdout()
        if isinstance(ex, BrokenPipeError):
            sys.exit(EXIT_ERROR)
        _error(f"cannot write to stdout: {ex}")


def _discard_stdout() -> None:
    """Send stdout to the null device, so that Python does not fail again when it exits."""
    # stdout has no file descriptor if a program replaced it, for example in a test
    with contextlib.suppress(OSError, ValueError):
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())


def _die_from_sigint() -> None:
    """
    End this process with SIGINT, the way that a program without a handler for Ctrl-C
    ends. A shell stops a loop or a script only if the command ended with SIGINT.
    """
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(OSError, ValueError):
            stream.flush()
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    os.kill(os.getpid(), signal.SIGINT)


def main() -> None:
    """
    Run the ``getmac`` command, then exit with one of these codes:

    - :data:`EXIT_FOUND` (``0``): getmac found the MAC (or the interface) and printed it.
    - :data:`EXIT_NOT_FOUND` (``1``): getmac did not find it.
    - :data:`EXIT_USAGE` (``2``): the arguments are not valid.
    - :data:`EXIT_ERROR` (``3``): the lookup failed with an error, or getmac failed to
      write to stdout.
    - :data:`EXIT_INTERRUPTED` (``130``): the user pressed Ctrl-C, on Windows.

    On other systems, Ctrl-C ends the process with SIGINT. A shell reports that as ``130``.
    """
    try:
        with warnings.catch_warnings():
            warnings.showwarning = _show_warning
            _main()
    except KeyboardInterrupt:
        # On Windows, a process that ends itself with SIGINT has exit code 2 (EXIT_USAGE)
        if not consts.WINDOWS:
            _die_from_sigint()
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
                f"argument --override-platform: '{args.override_platform}' is not the name "
                "of a platform."
                + (
                    _did_you_mean(platform, getmac.get_platform_names())
                    or f" Use one of these: {', '.join(sorted(getmac.get_platform_names()))}."
                )
            )
        settings.OVERRIDE_PLATFORM = platform

    forced = None
    if args.force_method:
        forced = getmac.get_method_by_name(args.force_method.strip())
        if forced is None:
            parser.error(
                f"argument --force-method: '{args.force_method}' is not the name of a method."
                + (
                    _did_you_mean(args.force_method, getmac.get_method_names())
                    or " Use --list-methods to see the methods for this platform."
                )
            )
        settings.FORCE_METHOD = args.force_method.strip().lower()

    if args.exclude_method:
        _exclude_methods(parser, args.exclude_method)

    if forced is not None and forced not in getmac.METHODS:
        parser.error(
            f"argument --force-method: '{args.force_method}' is also given to "
            "--exclude-method. Use only one of the two options for a method."
        )

    if args.list_methods:
        _list_methods(network_request=not args.NO_NET, as_json=args.json)
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
    except (RuntimeError, Warning) as ex:
        # There are no methods for the platform, or none of them work. The message gives
        # the cause. A warning is an exception here if Python makes warnings errors, for
        # example with "python -W error".
        if args.debug:
            traceback.print_exc()
        _error(str(ex))
    except Exception as ex:
        # For example, a method forced with --force-method raised an exception. getmac does
        # not catch the exceptions of a forced method.
        if args.debug:
            traceback.print_exc()
        _error(
            f"the lookup failed with an unexpected error ({type(ex).__name__}: {ex}).\n"
            f"If you think that this is a bug, report it at {ISSUES_URL}. "
            "Add '-v -dddd' to the same command, and include its output in the report."
        )

    if args.json:
        _print_json(_result_json(args, result or None))
    elif result:
        _print(result)

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
        value = getattr(args, name)
        # get_mac_address() reads an empty value as no value, and looks up the default
        # interface. The exception is ip6, for which an empty value is an address that
        # is not valid.
        if value or (name == "ip6" and value is not None):
            lookup, target = name, value

    return {
        "mac": result,
        "lookup": lookup,
        "target": target,
        "method": method,
        "platform": _platform(),
    }


if __name__ == "__main__":
    main()
