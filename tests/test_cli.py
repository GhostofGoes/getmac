import logging
import sys
from subprocess import PIPE, Popen
from typing import List

import pytest

from getmac import __version__, get_mac_address
from getmac.__main__ import build_parser, main
from getmac.variables import settings

BASE_CMD = [sys.executable, "-m", "getmac"]


def run_cmd(command: List[str]) -> str:
    stdout, stderr = Popen(command, stdout=PIPE, stderr=PIPE).communicate()
    return stdout.decode("utf-8").strip() + stderr.decode().strip()


@pytest.fixture(autouse=True)
def _restore_settings():
    """
    `main()` mutates the `settings` singleton via plain attribute assignment,
    not through anything `mocker.patch` can auto-undo, so snapshot/restore
    it around every test to avoid leaking state into other test modules.
    """
    orig = (settings.PORT, settings.DEBUG, settings.OVERRIDE_PLATFORM, settings.FORCE_METHOD)
    yield
    settings.PORT, settings.DEBUG, settings.OVERRIDE_PLATFORM, settings.FORCE_METHOD = orig


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


def test_main_calls_get_mac_address_with_defaults(mocker):
    mock_get_mac = mocker.patch("getmac.getmac.get_mac_address", return_value="00:11:22:33:44:55")
    mocker.patch.object(sys, "argv", ["getmac"])

    with pytest.raises(SystemExit):
        main()

    mock_get_mac.assert_called_once_with(
        interface=None, ip=None, ip6=None, hostname=None, network_request=True
    )


@pytest.mark.parametrize(
    ("flag", "value", "kwarg"),
    [
        ("-i", "eth0", "interface"),
        ("-4", "10.0.0.1", "ip"),
        ("-6", "::1", "ip6"),
        ("-n", "myhost", "hostname"),
    ],
)
def test_main_passes_through_target_args(mocker, flag, value, kwarg):
    mock_get_mac = mocker.patch("getmac.getmac.get_mac_address", return_value="00:11:22:33:44:55")
    mocker.patch.object(sys, "argv", ["getmac", flag, value])

    with pytest.raises(SystemExit):
        main()

    assert mock_get_mac.call_args.kwargs[kwarg] == value


def test_main_no_net_disables_network_request(mocker):
    mock_get_mac = mocker.patch("getmac.getmac.get_mac_address", return_value="00:11:22:33:44:55")
    mocker.patch.object(sys, "argv", ["getmac", "--no-network-requests"])

    with pytest.raises(SystemExit):
        main()

    assert mock_get_mac.call_args.kwargs["network_request"] is False


def test_main_exit_code_success(mocker, capsys):
    mocker.patch("getmac.getmac.get_mac_address", return_value="00:11:22:33:44:55")
    mocker.patch.object(sys, "argv", ["getmac"])

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 0
    assert capsys.readouterr().out.strip() == "00:11:22:33:44:55"


def test_main_exit_code_failure(mocker, capsys):
    mocker.patch("getmac.getmac.get_mac_address", return_value=None)
    mocker.patch.object(sys, "argv", ["getmac"])

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 1
    assert capsys.readouterr().out == ""


# --- settings mutation + logging ---------------------------------------------


def test_main_override_port_updates_setting(mocker):
    mocker.patch("getmac.getmac.get_mac_address", return_value="00:11:22:33:44:55")
    mocker.patch.object(sys, "argv", ["getmac", "--override-port", "44444"])

    with pytest.raises(SystemExit):
        main()

    assert settings.PORT == 44444


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


def test_main_override_platform_updates_setting(mocker):
    mocker.patch("getmac.getmac.get_mac_address", return_value="00:11:22:33:44:55")
    mocker.patch.object(sys, "argv", ["getmac", "--override-platform", " Linux "])

    with pytest.raises(SystemExit):
        main()

    assert settings.OVERRIDE_PLATFORM == "linux"


def test_main_force_method_updates_setting(mocker):
    mocker.patch("getmac.getmac.get_mac_address", return_value="00:11:22:33:44:55")
    mocker.patch.object(sys, "argv", ["getmac", "--force-method", " SomeMethod "])

    with pytest.raises(SystemExit):
        main()

    assert settings.FORCE_METHOD == "somemethod"


def test_main_debug_flag_updates_setting(mocker):
    mocker.patch("getmac.getmac.get_mac_address", return_value="00:11:22:33:44:55")
    mocker.patch.object(sys, "argv", ["getmac", "-dd"])

    with pytest.raises(SystemExit):
        main()

    assert settings.DEBUG == 2


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


# --- true end-to-end subprocess smoke tests ----------------------------------


def test_cli_main_basic():
    assert run_cmd(BASE_CMD) == get_mac_address()


def test_cli_help():
    assert "usage: getmac" in run_cmd([*BASE_CMD, "--help"])


def test_cli_version():
    assert run_cmd([*BASE_CMD, "--version"]).strip().endswith(__version__)
