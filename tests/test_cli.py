import platform
import sys
from subprocess import PIPE, Popen
from typing import List

from getmac import __version__, get_mac_address

BASE_CMD = [sys.executable, "-m", "getmac"]


def run_cmd(command: List[str]) -> str:
    stdout, stderr = Popen(command, stdout=PIPE, stderr=PIPE).communicate()
    return stdout.decode("utf-8").strip() + stderr.decode().strip()


def test_cli_main_basic():
    assert run_cmd(BASE_CMD) == get_mac_address()


def test_cli_main_verbose():
    assert get_mac_address() in run_cmd([*BASE_CMD, "--verbose"])


def test_cli_main_debug():
    assert get_mac_address() in run_cmd([*BASE_CMD, "--verbose", "--debug"])


def test_cli_main_invalid_interface():
    assert run_cmd([*BASE_CMD, "--interface", "INVALIDTESTINTERFACE"]) == ""


def test_cli_help():
    assert "usage: getmac" in run_cmd([*BASE_CMD, "--help"])


def test_cli_version():
    assert run_cmd([*BASE_CMD, "--version"]).strip().endswith(__version__)


def test_cli_multiple_debug_levels():
    assert get_mac_address() in run_cmd([*BASE_CMD, "-v", "-dd"])
    assert get_mac_address() in run_cmd([*BASE_CMD, "-v", "-ddd"])
    assert get_mac_address() in run_cmd([*BASE_CMD, "-v", "-dddd"])


def test_cli_no_net():
    assert get_mac_address(hostname="localhost") in run_cmd(
        [*BASE_CMD, "-n", "localhost", "--no-network-requests"]
    )


def test_cli_override_port():
    assert run_cmd(
        [*BASE_CMD, "-v", "-dd", "-4", "127.0.0.1", "--override-port", "44444"]
    )


def test_cli_localhost():
    assert run_cmd([*BASE_CMD, "-4", "127.0.0.1"])
    assert run_cmd([*BASE_CMD, "-n", "localhost"])
    assert run_cmd([*BASE_CMD, "--no-network-requests", "-4", "127.0.0.1"])
    assert run_cmd([*BASE_CMD, "--no-network-requests", "-n", "localhost"])


# TODO: figure out how to properly test CLI commands and isolate platform-specific behavior
def test_cli_override_platform():
    # TODO: proper test for this
    plat = platform.system().lower()
    assert run_cmd([*BASE_CMD, "-v", "-dd", "--override-platform", plat])


def test_cli_force_method():
    # TODO: proper test for this
    assert run_cmd([*BASE_CMD, "-v", "-dd", "--force-method", "InvalidMethod"])
