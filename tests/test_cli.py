import itertools
import logging
import os
import subprocess
import sys
from typing import Union

import pytest

from getmac import __version__, get_mac_address, getmac
from getmac.__main__ import build_parser, main
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
    )
    yield
    (
        settings.PORT,
        settings.DEBUG,
        settings.OVERRIDE_PLATFORM,
        settings.FORCE_METHOD,
        settings.ARP_TIMEOUT,
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
    assert args.override_platform is None
    assert args.force_method is None


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
        (["--override-port", "12345"], "override_port", 12345),
        (["--arp-timeout", "1.5"], "arp_timeout", 1.5),
        (["--arp-timeout", "0"], "arp_timeout", 0),
        (["--override-platform", "freebsd"], "override_platform", "freebsd"),
        (["--force-method", "IpNeighborShow"], "force_method", "IpNeighborShow"),
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


# --- argparse handling -------------------------------------------------------


@pytest.mark.parametrize(
    ("args", "error"),
    [
        *((a + b, "not allowed with argument") for a, b in itertools.combinations(TARGET_ARGS, 2)),
        (["--interface", "eth0", "--hostname", "myhost"], "not allowed with argument"),
        (["--override-port", "abc"], "argument --override-port: invalid int value: 'abc'"),
        (["--arp-timeout", "abc"], "argument --arp-timeout: not a number of seconds: 'abc'"),
        (["--arp-timeout=-1"], "argument --arp-timeout: must be 0 or more seconds: '-1'"),
        (["-i"], "argument -i/--interface: expected one argument"),
        (["--bogus"], "unrecognized arguments: --bogus"),
    ],
)
def test_main_argparse_errors(mock_get_mac, run_cli, args, error):
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


# --- settings mutation + logging ---------------------------------------------


@pytest.mark.parametrize(
    ("args", "attr", "expected"),
    [
        (["--override-port", "44444"], "PORT", 44444),
        (["--arp-timeout", "0.5"], "ARP_TIMEOUT", 0.5),
        (["--override-platform", " Linux "], "OVERRIDE_PLATFORM", "linux"),
        (["--override-platform", "FreeBSD"], "OVERRIDE_PLATFORM", "freebsd"),
        (["--force-method", " SomeMethod "], "FORCE_METHOD", "somemethod"),
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
    attrs = ("PORT", "DEBUG", "OVERRIDE_PLATFORM", "FORCE_METHOD")
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


def test_cli_version():
    proc = run_cmd("--version")
    assert proc.stdout == f"getmac {__version__}\n"
    assert proc.stderr == ""
    assert proc.returncode == 0


@pytest.mark.parametrize("flag", [None, "-v", "-d"])
def test_cli_logging_goes_to_stderr_only(flag):
    # An unknown forced method fails the lookup before any real command runs
    proc = run_cmd(*([flag] if flag else []), "--force-method", " BoGuS ", "-i", "eth0")

    assert proc.stdout == ""
    assert proc.returncode == 1
    if flag:
        assert "WARNING  Forcing method 'bogus' to be used for 'iface' lookup" in proc.stderr
        assert "ERROR    Invalid FORCE_METHOD method name 'bogus'\n" in proc.stderr
    else:
        assert proc.stderr == ""
