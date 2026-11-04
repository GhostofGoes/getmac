import itertools
import json
import logging
import os
import subprocess
import sys
import warnings
from typing import Union

import pytest

from getmac import __version__, get_mac_address, getmac
from getmac.__main__ import _join_negative_values, build_parser, main
from getmac.variables import consts, gvars, settings

BASE_CMD = [sys.executable, "-m", "getmac"]
MAC = "00:11:22:33:44:55"
FAKEOS_MAC = "aa:bb:cc:dd:ee:ff"
TARGET_ARGS = [["-i", "eth0"], ["-4", "10.0.0.1"], ["-6", "::1"], ["-n", "myhost"]]
# Python 3.14+ argparse colors its output if FORCE_COLOR is set, which breaks matching on it
NO_COLOR_ENV = {"PYTHON_COLORS": "0"}


def run_cmd(*args: str) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(
        [*BASE_CMD, *args],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, **NO_COLOR_ENV},
    )


@pytest.fixture(autouse=True)
def _restore_settings():
    """
    `main()` mutates the `settings` singleton via plain attribute assignment,
    not through anything `mocker.patch` can auto-undo, so snapshot/restore
    it around every test to avoid leaking state into other test modules.
    """
    orig = (
        settings.PORT,
        settings.DEBUG,
        settings.OVERRIDE_PLATFORM,
        settings.FORCE_METHOD,
        settings.ARP_TIMEOUT,
        settings.COMMAND_TIMEOUT,
    )
    yield
    (
        settings.PORT,
        settings.DEBUG,
        settings.OVERRIDE_PLATFORM,
        settings.FORCE_METHOD,
        settings.ARP_TIMEOUT,
        settings.COMMAND_TIMEOUT,
    ) = orig


@pytest.fixture
def run_cli(mocker, capsys):
    """
    Run `main()` in-process with the given arguments, returning
    ``(exit code, stdout, stderr)``.

    pytest attaches its log capture handlers to the root logger, which makes
    `logging.basicConfig()` in `main()` a silent no-op. Detach them while `main()`
    runs so the CLI's real logging setup is exercised, then put them (and the
    root level) back so the handler `main()` adds doesn't leak into other tests.
    """

    def _run_cli(*args: str) -> tuple[Union[int, str, None], str, str]:
        mocker.patch.object(sys, "argv", ["getmac", *args])
        mocker.patch.dict(os.environ, NO_COLOR_ENV)
        mocker.patch.object(gvars, "LAST_METHOD", gvars.LAST_METHOD)  # main() changes it
        root = logging.getLogger()
        orig_handlers, orig_level = root.handlers, root.level
        root.handlers = []
        try:
            with pytest.raises(SystemExit) as exc_info:
                main()
        finally:
            root.handlers = orig_handlers
            root.setLevel(orig_level)
        out, err = capsys.readouterr()
        return exc_info.value.code, out, err

    return _run_cli


@pytest.fixture
def mock_get_mac(mocker):
    return mocker.patch("getmac.getmac.get_mac_address", return_value=MAC)


class StubIface(getmac.Method):
    """Stands in for the method normally picked for the detected platform."""

    platforms = {consts.PLATFORM}
    method_type = "iface"

    def test(self) -> bool:
        return True

    def get(self, arg: str) -> str:  # noqa: ARG002
        return MAC


class StubFakeOsIface(StubIface):
    """Only picked if the platform is overridden to 'fakeos', or it's forced by name."""

    platforms = {"fakeos"}

    def get(self, arg: str) -> str:  # noqa: ARG002
        return FAKEOS_MAC


class StubIp4(StubIface):
    method_type = "ip4"


@pytest.fixture
def stub_methods(mocker):
    """
    Use the real `get_mac_address()` lookup logic, but with stub methods
    in place of the real ones (which would run commands or read files).
    """
    mocker.patch("getmac.getmac.METHODS", [StubIface, StubFakeOsIface, StubIp4])
    mocker.patch("getmac.getmac.METHOD_CACHE", dict.fromkeys(getmac.METHOD_CACHE))
    mocker.patch("getmac.getmac.FALLBACK_CACHE", {k: [] for k in getmac.FALLBACK_CACHE})


# --- build_parser() ----------------------------------------------------------


def test_build_parser_defaults():
    args = build_parser().parse_args([])
    assert args.interface is None
    assert args.ip is None
    assert args.ip6 is None
    assert args.hostname is None
    assert args.NO_NET is False
    assert args.verbose is False
    assert args.debug is None
    assert args.override_port is None
    assert args.arp_timeout is None
    assert args.command_timeout is None
    assert args.override_platform is None
    assert args.force_method is None
    assert args.default_interface is False
    assert args.exclude_method is None
    assert args.list_methods is False
    assert args.json is False


@pytest.mark.parametrize(
    ("argv", "attr", "expected"),
    [
        (["-i", "eth0"], "interface", "eth0"),
        (["-4", "10.0.0.1"], "ip", "10.0.0.1"),
        (["-6", "::1"], "ip6", "::1"),
        (["-n", "myhost"], "hostname", "myhost"),
        (["-N"], "NO_NET", True),
        (["--no-net"], "NO_NET", True),
        (["--no-network-requests"], "NO_NET", True),
        (["-v"], "verbose", True),
        (["-d"], "debug", 1),
        (["-dd"], "debug", 2),
        (["-dddd"], "debug", 4),
        (["-vdd"], "debug", 2),  # Short options can still be combined
        (["--override-port", "12345"], "override_port", 12345),
        (["--arp-timeout", "1.5"], "arp_timeout", 1.5),
        (["--arp-timeout", "0"], "arp_timeout", 0),
        (["--command-timeout", "2.5"], "command_timeout", 2.5),
        (["--command-timeout", "0"], "command_timeout", 0),
        (["--override-platform", "freebsd"], "override_platform", "freebsd"),
        (["--force-method", "IpNeighborShow"], "force_method", "IpNeighborShow"),
        (["-D"], "default_interface", True),
        (["--default-interface"], "default_interface", True),
        (["-E", "SysIfaceFile"], "exclude_method", ["SysIfaceFile"]),
        (["--exclude-method", "ArpFile"], "exclude_method", ["ArpFile"]),
        (
            ["--exclude-method", "ArpFile", "--exclude-method", "IpNeighborShow"],
            "exclude_method",
            ["ArpFile", "IpNeighborShow"],
        ),
        (["--list-methods"], "list_methods", True),
        (["--json"], "json", True),
    ],
)
def test_build_parser_flag_values(argv, attr, expected):
    args = build_parser().parse_args(argv)
    assert getattr(args, attr) == expected


def test_build_parser_mutually_exclusive_group():
    with pytest.raises(SystemExit) as exc_info:
        build_parser().parse_args(["-i", "eth0", "-4", "10.0.0.1"])
    assert exc_info.value.code == 2


# --- main() dispatch to get_mac_address() -----------------------------------


def test_main_calls_get_mac_address_with_defaults(mock_get_mac, run_cli):
    run_cli()

    mock_get_mac.assert_called_once_with(
        interface=None, ip=None, ip6=None, hostname=None, network_request=True
    )


@pytest.mark.parametrize(
    ("args", "kwarg", "value"),
    [
        (["-i", "eth0"], "interface", "eth0"),
        (["--interface", "eth0"], "interface", "eth0"),
        (["-4", "10.0.0.1"], "ip", "10.0.0.1"),
        (["--ip", "10.0.0.1"], "ip", "10.0.0.1"),
        (["-6", "::1"], "ip6", "::1"),
        (["--ip6", "fe80::1"], "ip6", "fe80::1"),
        (["-n", "myhost"], "hostname", "myhost"),
        (["--hostname", "myhost"], "hostname", "myhost"),
    ],
)
def test_main_passes_through_target_args(mock_get_mac, run_cli, args, kwarg, value):
    run_cli(*args)

    expected = {"interface": None, "ip": None, "ip6": None, "hostname": None}
    expected[kwarg] = value
    mock_get_mac.assert_called_once_with(**expected, network_request=True)


@pytest.mark.parametrize("flag", ["-N", "--no-net", "--no-network-requests"])
def test_main_no_net_disables_network_request(mock_get_mac, run_cli, flag):
    run_cli(flag, "-4", "10.0.0.1")

    mock_get_mac.assert_called_once_with(
        interface=None, ip="10.0.0.1", ip6=None, hostname=None, network_request=False
    )


def test_main_exit_code_success(mock_get_mac, run_cli):
    assert run_cli() == (0, f"{MAC}\n", "")
    mock_get_mac.assert_called_once()


def test_main_exit_code_failure(mock_get_mac, run_cli):
    mock_get_mac.return_value = None

    assert run_cli() == (1, "", "")
    mock_get_mac.assert_called_once()


# --- errors, warnings, and Ctrl-C ---------------------------------------------


@pytest.mark.parametrize("args", [[], ["-i", "eth0"], ["-D"]])
def test_main_runtime_error_is_a_message(mocker, run_cli, args):
    error = RuntimeError("All 3 'iface' methods failed to test!")
    mocker.patch("getmac.getmac.get_mac_address", side_effect=error)
    mocker.patch("getmac.getmac.get_default_interface", side_effect=error)

    assert run_cli(*args) == (
        3,
        "",
        "getmac: error: All 3 'iface' methods failed to test!\n",
    )


@pytest.mark.parametrize("args", [[], ["-D"]])
def test_main_unexpected_error_asks_for_a_report(mocker, run_cli, args):
    error = OSError("boom")
    mocker.patch("getmac.getmac.get_mac_address", side_effect=error)
    mocker.patch("getmac.getmac.get_default_interface", side_effect=error)

    code, out, err = run_cli(*args)

    assert (code, out) == (3, "")
    assert err.startswith("getmac: error: unexpected OSError: boom\n")
    assert "https://github.com/GhostofGoes/getmac/issues" in err
    assert "Traceback" not in err


@pytest.mark.parametrize("error", [RuntimeError("no methods"), OSError("boom")])
def test_main_error_with_debug_prints_traceback(mock_get_mac, run_cli, error):
    mock_get_mac.side_effect = error

    code, out, err = run_cli("-d")

    assert (code, out) == (3, "")
    assert "Traceback (most recent call last):" in err
    assert f"{type(error).__name__}: {error}" in err
    assert "getmac: error: " in err


@pytest.mark.parametrize("args", [[], ["-D"], ["--list-methods"]])
def test_main_ctrl_c_exits_130_quietly(mocker, run_cli, args):
    mocker.patch("getmac.getmac.get_mac_address", side_effect=KeyboardInterrupt)
    mocker.patch("getmac.getmac.get_default_interface", side_effect=KeyboardInterrupt)
    mocker.patch("getmac.__main__._list_methods", side_effect=KeyboardInterrupt)

    assert run_cli(*args) == (130, "", "")


@pytest.mark.parametrize("flag", [None, "-v"])
def test_main_warnings_are_one_line(mock_get_mac, run_cli, flag):
    def _lookup(**_kwargs):
        warnings.warn("No methods for platform 'x'!", RuntimeWarning, stacklevel=2)
        return MAC

    mock_get_mac.side_effect = _lookup
    original = warnings.showwarning

    assert run_cli(*([flag] if flag else [])) == (
        0,
        f"{MAC}\n",
        "getmac: warning: No methods for platform 'x'!\n",
    )
    assert warnings.showwarning is original  # Put back when main() is done


# --- argparse handling -------------------------------------------------------


@pytest.mark.parametrize(
    ("args", "error"),
    [
        *((a + b, "not allowed with argument") for a, b in itertools.combinations(TARGET_ARGS, 2)),
        (["--interface", "eth0", "--hostname", "myhost"], "not allowed with argument"),
        (["--override-port", "abc"], "argument --override-port: not a port number: 'abc'"),
        *(
            (
                ["--override-port", port],
                f"argument --override-port: must be a port from 1 to 65535: '{port}'",
            )
            for port in ("0", "65536", "-1", "-80")
        ),
        (["--arp-timeout", "abc"], "argument --arp-timeout: not a number of seconds: 'abc'"),
        (["--arp-timeout=-1"], "argument --arp-timeout: must be 0 or more seconds: '-1'"),
        # Not "expected one argument" (argparse takes -1 for an option, because of -4 and -6)
        (["--arp-timeout", "-1"], "argument --arp-timeout: must be 0 or more seconds: '-1'"),
        (["--arp-timeout", "-.5"], "argument --arp-timeout: must be 0 or more seconds: '-.5'"),
        (
            ["--command-timeout", "-1.5"],
            "argument --command-timeout: must be 0 or more seconds: '-1.5'",
        ),
        *(
            (
                ["--arp-timeout", value],
                f"argument --arp-timeout: not a number of seconds: '{value}'",
            )
            for value in ("nan", "inf", "-inf", "Infinity")
        ),
        *(
            (
                ["--command-timeout", value],
                f"argument --command-timeout: not a number of seconds: '{value}'",
            )
            for value in ("nan", "inf")
        ),
        (["--arp-timeout"], "argument --arp-timeout: expected one argument"),
        (
            ["--override-platform", "BoGuS"],
            "argument --override-platform: unknown platform 'BoGuS' (choose from android, ",
        ),
        (
            ["--force-method", "BoGuS"],
            "argument --force-method: unknown method 'BoGuS' (--list-methods shows",
        ),
        (
            ["--force-method", "arpfile", "-E", "ArpFile"],
            "argument --force-method: 'arpfile' is excluded with --exclude-method",
        ),
        (
            ["--command-timeout", "abc"],
            "argument --command-timeout: not a number of seconds: 'abc'",
        ),
        (
            ["--command-timeout=-1"],
            "argument --command-timeout: must be 0 or more seconds: '-1'",
        ),
        (["-i"], "argument -i/--interface: expected one argument"),
        (["-D", "-i", "eth0"], "not allowed with argument"),
        (["--exclude-method", "BoGuS"], "argument --exclude-method: unknown method 'BoGuS'"),
        (["--list-methods", "-4", "10.0.0.1"], "not allowed with argument"),
        (["--bogus"], "unrecognized arguments: --bogus"),
        # The start of an option isn't accepted (allow_abbrev=False)
        (["--int", "eth0"], "unrecognized arguments: --int eth0"),
        (["--no", "-4", "10.0.0.1"], "arguments: --no (did you mean '--no-net'?)\n"),
        # Suggestions for typos
        (
            ["--interfaces", "eth0"],
            "unrecognized arguments: --interfaces eth0 (did you mean '--interface'?)\n",
        ),
        (
            ["--interfaces=eth0", "--no-nett", "--zzzzzzzz"],
            (
                "unrecognized arguments: --interfaces=eth0 --no-nett --zzzzzzzz (did you mean "
                "'--interface' for '--interfaces=eth0', '--no-net' for '--no-nett'?)\n"
            ),
        ),
        (["-z"], "unrecognized arguments: -z\n"),  # Short options are too short to guess
        (
            ["--override-platform", "Linx"],
            "argument --override-platform: unknown platform 'Linx' (did you mean 'linux'?)\n",
        ),
        (
            ["--force-method", "ipneighbourshow"],
            (
                "argument --force-method: unknown method 'ipneighbourshow' "
                "(did you mean 'IpNeighborShow'?)\n"
            ),
        ),
        (
            ["-E", "arpfil"],
            "argument --exclude-method: unknown method 'arpfil' (did you mean 'ArpFile'?)\n",
        ),
    ],
)
def test_main_argparse_errors(mock_get_mac, run_cli, mocker, args, error):
    mocker.patch("getmac.getmac.METHODS", list(getmac.METHODS))  # -E removes from it

    code, out, err = run_cli(*args)

    assert code == 2
    assert out == ""
    assert "getmac: error: " in err
    assert error in err
    mock_get_mac.assert_not_called()


def test_main_version(mock_get_mac, run_cli):
    assert run_cli("--version") == (0, f"getmac {__version__}\n", "")
    mock_get_mac.assert_not_called()


@pytest.mark.parametrize("flag", ["-h", "--help"])
def test_main_help(mock_get_mac, run_cli, flag):
    assert run_cli(flag) == (0, build_parser().format_help(), "")
    mock_get_mac.assert_not_called()


@pytest.mark.parametrize("columns", ["40", "80", "200"])
def test_help_text(mocker, columns):
    mocker.patch.dict(os.environ, {"COLUMNS": columns})
    text = build_parser().format_help()

    assert "With no arguments, prints the MAC of the default interface." in text
    assert "\nexamples:\n  getmac                    MAC of the default interface\n" in text
    assert "\nexit codes:\n" in text
    assert "  3    error (printed to stderr)\n" in text
    assert "docs:   https://ghostofgoes.github.io/getmac/cli.html\n" in text
    assert "issues: https://github.com/GhostofGoes/getmac/issues\n" in text
    # Options in the help text aren't split at the '-', e.g. '--list-' and 'methods'
    assert not any(line.endswith("-") for line in text.splitlines())


# --- settings mutation + logging ---------------------------------------------


@pytest.mark.parametrize(
    ("args", "attr", "expected"),
    [
        (["--override-port", "44444"], "PORT", 44444),
        (["--arp-timeout", "0.5"], "ARP_TIMEOUT", 0.5),
        (["--command-timeout", "3"], "COMMAND_TIMEOUT", 3.0),
        (["--command-timeout", "0"], "COMMAND_TIMEOUT", 0),
        (["--override-platform", " Linux "], "OVERRIDE_PLATFORM", "linux"),
        (["--override-platform", "FreeBSD"], "OVERRIDE_PLATFORM", "freebsd"),
        (["--force-method", " ArpFile "], "FORCE_METHOD", "arpfile"),
        (["--force-method", "IpNeighborShow"], "FORCE_METHOD", "ipneighborshow"),
        (["-d"], "DEBUG", 1),
        (["--debug"], "DEBUG", 1),
        (["-dd"], "DEBUG", 2),
        (["-d", "-d"], "DEBUG", 2),
        (["-dddd"], "DEBUG", 4),
    ],
)
def test_main_updates_settings_before_lookup(mock_get_mac, run_cli, args, attr, expected):
    settings.DEBUG = 0  # conftest.py sets DEBUG=4 for the whole session
    seen = {}

    def _lookup(**_kwargs):
        seen[attr] = getattr(settings, attr)
        return MAC

    mock_get_mac.side_effect = _lookup

    assert run_cli(*args)[0] == 0
    assert seen[attr] == expected  # In effect during the lookup...
    assert getattr(settings, attr) == expected  # ...and still set afterwards


@pytest.mark.usefixtures("mock_get_mac")
@pytest.mark.parametrize("args", [[], ["-v"], ["--verbose"], ["-N"], ["-i", "eth0"]])
def test_main_leaves_settings_alone_without_flags(run_cli, args):
    settings.DEBUG = 0
    attrs = (
        "PORT",
        "DEBUG",
        "OVERRIDE_PLATFORM",
        "FORCE_METHOD",
        "ARP_TIMEOUT",
        "COMMAND_TIMEOUT",
    )
    before = {a: getattr(settings, a) for a in attrs}

    run_cli(*args)

    assert {a: getattr(settings, a) for a in attrs} == before


def test_main_override_port_logs_debug_message(mocker, caplog):
    mocker.patch("getmac.getmac.get_mac_address", return_value="00:11:22:33:44:55")
    mocker.patch.object(sys, "argv", ["getmac", "--override-port", "44444"])
    original_port = settings.PORT

    with caplog.at_level(logging.DEBUG, logger="getmac"), pytest.raises(SystemExit):
        main()

    matches = [
        r
        for r in caplog.records
        if r.name == "getmac"
        and r.levelno == logging.DEBUG
        and "44444" in r.message
        and str(original_port) in r.message
    ]
    assert matches, f"expected a debug record mentioning the port override, got: {caplog.records}"


@pytest.mark.parametrize("flag", [None, "-v", "--verbose", "-d", "--debug", "-dd"])
@pytest.mark.parametrize("mac", [MAC, None])
def test_main_logging_goes_to_stderr_only(mock_get_mac, run_cli, flag, mac):
    def _lookup(**_kwargs):
        gvars.log.debug("debug from lookup")
        gvars.log.warning("warning from lookup")
        return mac

    mock_get_mac.side_effect = _lookup
    original_port = settings.PORT

    code, out, err = run_cli(*([flag] if flag else []), "--override-port", "44444")

    assert code == (0 if mac else 1)
    # stdout is only ever the MAC, so it's safe to use in scripts
    assert out == (f"{mac}\n" if mac else "")
    if flag:
        assert err == (
            f"DEBUG    Using UDP port 44444 (overriding the default port {original_port})\n"
            "DEBUG    debug from lookup\n"
            "WARNING  warning from lookup\n"
        )
    else:
        assert err == ""


def test_main_verbose_configures_logging(mocker):
    mock_basic_config = mocker.patch("logging.basicConfig")
    mocker.patch("getmac.getmac.get_mac_address", return_value="00:11:22:33:44:55")
    mocker.patch.object(sys, "argv", ["getmac", "--verbose"])

    with pytest.raises(SystemExit):
        main()

    mock_basic_config.assert_called_once_with(
        format="%(levelname)-8s %(message)s", level=logging.DEBUG, stream=sys.stderr
    )


def test_main_debug_configures_logging(mocker):
    mock_basic_config = mocker.patch("logging.basicConfig")
    mocker.patch("getmac.getmac.get_mac_address", return_value="00:11:22:33:44:55")
    mocker.patch.object(sys, "argv", ["getmac", "-d"])

    with pytest.raises(SystemExit):
        main()

    mock_basic_config.assert_called_once()


def test_main_no_flags_skips_logging_config(mocker):
    mock_basic_config = mocker.patch("logging.basicConfig")
    mocker.patch("getmac.getmac.get_mac_address", return_value="00:11:22:33:44:55")
    mocker.patch.object(sys, "argv", ["getmac"])

    with pytest.raises(SystemExit):
        main()

    mock_basic_config.assert_not_called()


# --- overrides reach the real lookup logic (with stub methods) ---------------


@pytest.mark.parametrize(
    ("args", "expected_mac", "expected_log"),
    [
        ([], MAC, None),
        (
            ["--override-platform", " FakeOS "],
            FAKEOS_MAC,
            (
                "WARNING  Platform override is set, using 'fakeos' as platform instead of "
                f"detected platform '{consts.PLATFORM}'\n"
            ),
        ),
        (
            ["--force-method", " StubFakeOsIface "],
            FAKEOS_MAC,
            (
                "WARNING  Forcing method 'stubfakeosiface' to be used for 'iface' lookup "
                "(arg: 'eth0')\n"
            ),
        ),
    ],
)
@pytest.mark.usefixtures("stub_methods")
def test_main_overrides_change_method_used(run_cli, args, expected_mac, expected_log):
    code, out, err = run_cli("-v", "-i", "eth0", *args)

    assert code == 0
    assert out == f"{expected_mac}\n"
    if expected_log:
        assert expected_log in err
    else:
        assert "WARNING" not in err


@pytest.mark.parametrize(
    ("args", "expected_port"),
    [(["--override-port", "44444"], 44444), (["-N", "--override-port", "44444"], None)],
)
@pytest.mark.usefixtures("stub_methods")
def test_main_override_port_used_for_udp_packet(run_cli, mocker, args, expected_port):
    mock_socket = mocker.patch("getmac.getmac.socket.socket")

    assert run_cli("-4", "192.0.2.1", *args) == (0, f"{MAC}\n", "")

    if expected_port:
        mock_socket.return_value.sendto.assert_called_once_with(b"", ("192.0.2.1", expected_port))
    else:
        mock_socket.assert_not_called()


# --- --default-interface -----------------------------------------------------


@pytest.mark.parametrize("flag", ["-D", "--default-interface"])
def test_main_default_interface(mock_get_mac, run_cli, mocker, flag):
    mock_iface = mocker.patch("getmac.getmac.get_default_interface", return_value="eth0")

    assert run_cli(flag) == (0, "eth0\n", "")
    mock_iface.assert_called_once_with()
    mock_get_mac.assert_not_called()


def test_main_default_interface_not_found(mock_get_mac, run_cli, mocker):
    mocker.patch("getmac.getmac.get_default_interface", return_value=None)

    assert run_cli("-D") == (1, "", "")
    mock_get_mac.assert_not_called()


# --- --exclude-method --------------------------------------------------------


class StubIfaceFallback(StubIface):
    """A second iface method, after StubIface."""

    def get(self, arg: str) -> str:  # noqa: ARG002
        return FAKEOS_MAC


@pytest.mark.parametrize("name", ["StubIface", "stubiface", " STUBIFACE "])
@pytest.mark.usefixtures("stub_methods")
def test_main_exclude_method(run_cli, mocker, name):
    mocker.patch("getmac.getmac.METHODS", [StubIface, StubIfaceFallback, StubIp4])

    assert run_cli("-i", "eth0", "--exclude-method", name) == (0, f"{FAKEOS_MAC}\n", "")
    assert getmac.METHODS == [StubIfaceFallback, StubIp4]


@pytest.mark.usefixtures("stub_methods")
def test_main_exclude_method_unknown_leaves_methods_alone(run_cli):
    before = list(getmac.METHODS)

    assert run_cli("--exclude-method", "StubIp4", "--exclude-method", "nope")[0] == 2
    assert getmac.METHODS == before


@pytest.mark.usefixtures("stub_methods")
def test_main_exclude_method_named_twice(run_cli):
    code, out, _ = run_cli(
        "-4", "10.0.0.1", "-N", "-E", "StubIface", "--exclude-method", "stubiface"
    )

    assert (code, out) == (0, f"{MAC}\n")
    assert getmac.METHODS == [StubFakeOsIface, StubIp4]


# --- --list-methods ----------------------------------------------------------


class StubFailingIface(StubIface):
    def test(self) -> bool:
        return False


class StubRaisingIface(StubIface):
    def test(self) -> bool:
        raise OSError("boom")


class StubNetIp4(StubIp4):
    network_request = True


class StubOtherDefaultIface(StubIface):
    platforms = {"other"}
    method_type = "default_iface"


class StubIp(StubIface):
    method_type = "ip"


LIST_METHODS = [
    StubNetIp4,
    StubFailingIface,
    StubIface,
    StubRaisingIface,
    StubIfaceFallback,
    StubFakeOsIface,
    StubIp4,
    StubIp,
    StubOtherDefaultIface,
]


@pytest.mark.parametrize(
    ("args", "expected_ip4"),
    [
        (
            [],
            ["StubNetIp4", "primary"],
        ),
        (["-N"], ["StubNetIp4", "skipped (sends packets, and --no-net is set)"]),
    ],
)
@pytest.mark.usefixtures("stub_methods")
def test_main_list_methods(mock_get_mac, run_cli, mocker, args, expected_ip4):
    mocker.patch("getmac.getmac.METHODS", list(LIST_METHODS))
    ip4_status = "fallback" if expected_ip4[1] == "primary" else "primary"

    def row(name: str, status: str) -> str:
        return f"  {name:<28} {status}\n"

    expected = (
        f"Platform: {consts.PLATFORM}\n"
        "\nip4:\n"
        + row(*expected_ip4)
        + row("StubIp4", ip4_status)
        + row("StubIp", "fallback")
        + "\nip6:\n"
        + row("StubIp", "primary")
        + "\niface:\n"
        + row("StubFailingIface", "doesn't work here (test() failed)")
        + row("StubIface", "primary")
        + row("StubRaisingIface", "doesn't work here (test() failed)")
        + row("StubIfaceFallback", "fallback")
        + "\ndefault_iface:\n"
        + row("StubOtherDefaultIface", "primary")
    )

    assert run_cli("--list-methods", *args) == (0, expected, "")
    mock_get_mac.assert_not_called()


@pytest.mark.usefixtures("stub_methods")
def test_main_list_methods_override_platform(run_cli):
    code, out, _ = run_cli("--list-methods", "--override-platform", " FakeOS ")

    assert code == 0
    assert out == (
        "Platform: fakeos\n"
        "\nip4:\n  (none)\n"
        "\nip6:\n  (none)\n"
        f"\niface:\n  {'StubFakeOsIface':<28} primary\n"
        "\ndefault_iface:\n  (none)\n"
    )


@pytest.mark.usefixtures("stub_methods")
def test_main_list_methods_override_platform_and_exclude(run_cli):
    code, out, _ = run_cli(
        "--list-methods", "--override-platform", "fakeos", "-E", "StubFakeOsIface"
    )

    assert code == 0
    assert out == (
        "Platform: fakeos\n"
        "\nip4:\n  (none)\n"
        "\nip6:\n  (none)\n"
        "\niface:\n  (none)\n"
        "\ndefault_iface:\n  (none)\n"
    )


# --- --json --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("args", "lookup", "target"),
    [
        (["-i", "eth0"], "interface", "eth0"),
        (["-4", "192.0.2.1", "-N"], "ip", "192.0.2.1"),
    ],
)
@pytest.mark.usefixtures("stub_methods")
def test_main_json(run_cli, args, lookup, target):
    gvars.LAST_METHOD = "FromAnEarlierLookup"
    code, out, err = run_cli("--json", *args)

    assert (code, err) == (0, "")
    assert out.count("\n") == 1  # One line, since stdout isn't a terminal
    assert json.loads(out) == {
        "mac": MAC,
        "lookup": lookup,
        "target": target,
        "method": "StubIp4" if lookup == "ip" else "StubIface",
        "platform": consts.PLATFORM,
    }


@pytest.mark.usefixtures("stub_methods")
def test_main_json_not_found(run_cli, mocker):
    mocker.patch.object(StubFakeOsIface, "get", return_value=None)
    gvars.LAST_METHOD = "FromAnEarlierLookup"

    code, out, err = run_cli("--json", "-i", "eth9", "--override-platform", "fakeos")

    assert (code, err) == (1, "")
    assert json.loads(out) == {
        "mac": None,
        "lookup": "interface",
        "target": "eth9",
        "method": None,
        "platform": "fakeos",
    }


@pytest.mark.parametrize(("method", "expected"), [("SysIfaceFile", "SysIfaceFile"), ("", None)])
@pytest.mark.parametrize("args", [[], ["-n", "localhost"]])
def test_main_json_default_and_hostname(mock_get_mac, run_cli, args, method, expected):
    def _lookup(**_kwargs):
        gvars.LAST_METHOD = method  # E.g. empty for localhost, which doesn't use a method
        return MAC

    mock_get_mac.side_effect = _lookup

    code, out, _ = run_cli("--json", *args)

    assert code == 0
    assert json.loads(out) == {
        "mac": MAC,
        "lookup": "hostname" if args else "default",
        "target": "localhost" if args else None,
        "method": expected,
        "platform": consts.PLATFORM,
    }


@pytest.mark.parametrize("iface", ["eth0", None])
def test_main_json_default_interface(mock_get_mac, run_cli, mocker, iface):
    def _default_interface():
        gvars.LAST_METHOD = "DefaultIfaceIpRoute"
        return iface

    mocker.patch("getmac.getmac.get_default_interface", side_effect=_default_interface)

    code, out, err = run_cli("-D", "--json")

    assert (code, err) == (0 if iface else 1, "")
    assert json.loads(out) == {
        "interface": iface,
        "method": "DefaultIfaceIpRoute" if iface else None,
        "platform": consts.PLATFORM,
    }
    mock_get_mac.assert_not_called()


def test_main_json_is_indented_in_a_terminal(mock_get_mac, run_cli, mocker):
    mocker.patch.object(sys.stdout, "isatty", return_value=True)

    code, out, _ = run_cli("--json")

    assert code == 0
    assert out.startswith('{\n  "mac": "00:11:22:33:44:55",\n')
    mock_get_mac.assert_called_once()


def test_main_json_error_prints_no_json(mock_get_mac, run_cli):
    mock_get_mac.side_effect = RuntimeError("no methods")

    assert run_cli("--json") == (3, "", "getmac: error: no methods\n")


@pytest.mark.usefixtures("stub_methods")
def test_main_list_methods_json(mock_get_mac, run_cli, mocker):
    mocker.patch("getmac.getmac.METHODS", list(LIST_METHODS))

    code, out, err = run_cli("--list-methods", "--json", "-N")

    assert (code, err) == (0, "")
    assert json.loads(out) == {
        "platform": consts.PLATFORM,
        "methods": {
            "ip4": [
                {"name": "StubNetIp4", "status": "skipped"},
                {"name": "StubIp4", "status": "primary"},
                {"name": "StubIp", "status": "fallback"},
            ],
            "ip6": [{"name": "StubIp", "status": "primary"}],
            "iface": [
                {"name": "StubFailingIface", "status": "failed"},
                {"name": "StubIface", "status": "primary"},
                {"name": "StubRaisingIface", "status": "failed"},
                {"name": "StubIfaceFallback", "status": "fallback"},
            ],
            "default_iface": [{"name": "StubOtherDefaultIface", "status": "primary"}],
        },
    }
    mock_get_mac.assert_not_called()


# --- true end-to-end subprocess smoke tests ----------------------------------


def test_cli_main_basic():
    proc = run_cmd()
    assert proc.stdout == f"{get_mac_address()}\n"
    assert proc.stderr == ""
    assert proc.returncode == 0


def test_cli_help():
    proc = run_cmd("--help")
    assert "usage: getmac" in proc.stdout
    assert proc.stderr == ""
    assert proc.returncode == 0


def test_cli_default_interface():
    proc = run_cmd("--default-interface")
    iface = getmac.get_default_interface()
    assert proc.stdout == (f"{iface}\n" if iface else "")
    assert proc.stderr == ""
    assert proc.returncode == (0 if iface else 1)


def test_cli_list_methods():
    proc = run_cmd("--list-methods")
    assert proc.stdout.startswith(f"Platform: {consts.PLATFORM}\n")
    for method_type in getmac.METHOD_CACHE:
        assert f"\n{method_type}:\n" in proc.stdout
    assert proc.stderr == ""
    assert proc.returncode == 0


def test_cli_json():
    proc = run_cmd("--json")
    mac = get_mac_address()
    result = json.loads(proc.stdout)

    assert result["mac"] == mac
    assert result["lookup"] == "default"
    assert result["platform"] == consts.PLATFORM
    assert proc.stderr == ""
    assert proc.returncode == (0 if mac else 1)


def test_cli_version():
    proc = run_cmd("--version")
    assert proc.stdout == f"getmac {__version__}\n"
    assert proc.stderr == ""
    assert proc.returncode == 0


@pytest.mark.parametrize("flag", [None, "-v", "-d"])
def test_cli_logging_goes_to_stderr_only(flag):
    # An IPv6 address without a ':' fails the lookup before any real command runs
    proc = run_cmd(*([flag] if flag else []), "--override-port", "44444", "-6", "BoGuS")

    assert proc.stdout == ""
    assert proc.returncode == 1
    if flag:
        assert "DEBUG    Using UDP port 44444" in proc.stderr
        assert "ERROR    Invalid IPv6 address (no ':'): BoGuS\n" in proc.stderr
    else:
        assert proc.stderr == ""


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        ([], []),
        (["-i", "eth0"], ["-i", "eth0"]),
        (["--arp-timeout", "-1", "-v"], ["--arp-timeout=-1", "-v"]),
        (["--override-port", "-80"], ["--override-port=-80"]),
        (["--command-timeout", "-.5"], ["--command-timeout=-.5"]),
        (["--arp-timeout", "-1e3"], ["--arp-timeout=-1e3"]),
        (["--arp-timeout", "-inf"], ["--arp-timeout=-inf"]),
        (["--arp-timeout", "-Infinity"], ["--arp-timeout=-Infinity"]),
        (["--arp-timeout", "1"], ["--arp-timeout", "1"]),
        (["--arp-timeout", "-v"], ["--arp-timeout", "-v"]),  # Not a number
        (["--arp-timeout", "-4", "10.0.0.1"], ["--arp-timeout=-4", "10.0.0.1"]),
        (["--arp-timeout"], ["--arp-timeout"]),
        (["-i", "-1"], ["-i", "-1"]),  # Only for options that take a number
        (["--", "--arp-timeout", "-1"], ["--", "--arp-timeout", "-1"]),
    ],
)
def test_join_negative_values(argv, expected):
    assert _join_negative_values(argv) == expected
