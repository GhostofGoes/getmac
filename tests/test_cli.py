# -*- coding: utf-8 -*-

"""
Tests of the command line. These run "python -m getmac" in another process, on
the real system: the other tests can't use the system (see conftest.py), these
show that the whole thing works on it.
"""

import platform
import sys
from subprocess import PIPE, Popen

import pytest

from getmac import __version__, get_mac_address

PY2 = sys.version_info[0] == 2
BASE_CMD = [sys.executable, "-m", "getmac"]


def run(command):
    # type: (list) -> tuple
    """Run a command, and return its exit code, output and errors."""
    process = Popen(command, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    return (
        process.returncode,
        stdout.decode("utf-8", "replace").strip(),
        stderr.decode("utf-8", "replace"),
    )


def run_cmd(command):
    # type: (list) -> str
    return run(command)[1]


@pytest.fixture(scope="module")
def default_mac():
    """
    The MAC of the default interface of the system the tests are run on, or an
    empty string if it doesn't have one (e.g. there's no network). It's looked up
    in another process, like the commands it's compared with.
    """
    script = "import getmac; print(getmac.get_mac_address() or '')"
    code, stdout, stderr = run([sys.executable, "-c", script])
    assert code == 0, stderr
    return stdout


def test_cli_main_basic(default_mac):
    code, stdout, _ = run(BASE_CMD)
    assert stdout == default_mac
    # The exit code says if a MAC was found
    assert code == (0 if default_mac else 1)


def test_cli_main_verbose(default_mac):
    assert default_mac in run_cmd(BASE_CMD + ["--verbose"])


def test_cli_main_debug(default_mac):
    assert default_mac in run_cmd(BASE_CMD + ["--verbose", "--debug"])


def test_cli_main_invalid_interface():
    assert run_cmd(BASE_CMD + ["--interface", "INVALIDTESTINTERFACE"]) == ""


def test_cli_help():
    assert run_cmd(BASE_CMD + ["--help"]) != ""


@pytest.mark.skipif(
    PY2,
    reason="This doesn't work in Python 2.7 "
    "and I don't care enough to figure out why",
)
def test_cli_version():
    assert __version__ in run_cmd(BASE_CMD + ["--version"])


def test_cli_multiple_debug_levels(default_mac):
    assert default_mac in run_cmd(BASE_CMD + ["-v", "-dd"])
    assert default_mac in run_cmd(BASE_CMD + ["-v", "-ddd"])
    assert default_mac in run_cmd(BASE_CMD + ["-v", "-dddd"])


def test_cli_no_net():
    assert get_mac_address(hostname="localhost") in run_cmd(
        BASE_CMD + ["-n", "localhost", "--no-network-requests"]
    )


def test_cli_override_port():
    assert (
        run_cmd(BASE_CMD + ["-v", "-dd", "-4", "127.0.0.1", "--override-port", "44444"])
        != ""
    )


def test_cli_localhost():
    assert run_cmd(BASE_CMD + ["-4", "127.0.0.1"]) != ""
    assert run_cmd(BASE_CMD + ["-n", "localhost"]) != ""
    assert run_cmd(BASE_CMD + ["--no-network-requests", "-4", "127.0.0.1"]) != ""
    assert run_cmd(BASE_CMD + ["--no-network-requests", "-n", "localhost"]) != ""


# TODO: figure out how to properly test CLI commands and isolate platform-specific behavior
def test_cli_override_platform(default_mac):
    plat = platform.system().lower()
    assert run_cmd(BASE_CMD + ["-v", "-dd", "--override-platform", plat]) == default_mac
