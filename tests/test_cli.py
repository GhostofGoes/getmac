# -*- coding: utf-8 -*-

import sys
from subprocess import PIPE, Popen

import pytest

from getmac import __version__, get_mac_address

PY2 = sys.version_info[0] == 2
BASE_CMD = [sys.executable, '-m', 'getmac']


def run_cmd(command):
    stdout, _ = Popen(command, stdout=PIPE, stderr=PIPE).communicate()
    return stdout.decode('utf-8').strip()


def test_cli_main_basic():
    assert run_cmd(BASE_CMD) == get_mac_address()


def test_cli_main_verbose():
    assert get_mac_address() in run_cmd(BASE_CMD + ['--verbose'])


def test_cli_main_debug():
    assert get_mac_address() in run_cmd(BASE_CMD + ['--verbose', '--debug'])


def test_cli_main_invalid_interface():
    assert run_cmd(BASE_CMD + ['--interface', 'INVALIDTESTINTERFACE']) == ''


def test_cli_help():
    assert run_cmd(BASE_CMD + ['--help']) != ''


@pytest.mark.skipif(
    PY2, reason="This doesn't work in Python 2.7 "
                "and I don't care enough to figure out why")
def test_cli_version():
    assert __version__ in run_cmd(BASE_CMD + ['--version'])


def test_cli_multiple_debug_levels():
    assert get_mac_address() in run_cmd(BASE_CMD + ['-v', '-dd'])
    assert get_mac_address() in run_cmd(BASE_CMD + ['-v', '-ddd'])
    assert get_mac_address() in run_cmd(BASE_CMD + ['-v', '-dddd'])


def test_cli_no_net():
    assert get_mac_address(hostname='localhost') in run_cmd(
        BASE_CMD + ['-n', 'localhost', '--no-network-requests'])


def test_cli_localhost():
    assert run_cmd(BASE_CMD + ['-4', '127.0.0.1']) != ''
    assert run_cmd(BASE_CMD + ['-n', 'localhost']) != ''
    assert run_cmd(BASE_CMD + ['--no-network-requests', '-4', '127.0.0.1']) != ''
    assert run_cmd(BASE_CMD + ['--no-network-requests', '-n', 'localhost']) != ''
