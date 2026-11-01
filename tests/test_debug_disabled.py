# SPDX-FileCopyrightText: 2017-2026 Christopher Goes
# SPDX-License-Identifier: MIT

"""
Lookups with debugging turned off, which is the default outside of the tests.

conftest.py turns on all debug logging (``settings.DEBUG = 4``), so the rest of the
tests only take the branches where debug logging is on. These tests take the other
side of those branches, and a few branches that don't depend on the debug level.
"""

import logging
import socket
from subprocess import CalledProcessError

import pytest

from getmac import getmac, utils
from getmac.variables import consts, gvars, settings

MAC = "00:11:22:33:44:55"


@pytest.fixture(autouse=True)
def _debug_off(mocker):
    mocker.patch.object(settings, "DEBUG", 0)


@pytest.fixture(autouse=True)
def _empty_caches(mocker):
    mocker.patch("getmac.getmac.METHOD_CACHE", dict.fromkeys(getmac.METHOD_CACHE))
    mocker.patch("getmac.getmac.FALLBACK_CACHE", {k: [] for k in getmac.FALLBACK_CACHE})
    mocker.patch.object(gvars, "DEFAULT_IFACE", "")


@pytest.fixture(autouse=True)
def mock_socket(mocker):
    """Don't send the UDP packet used to populate the ARP table onto the network."""
    return mocker.patch("socket.socket")


@pytest.fixture
def debug_logs(caplog):
    """Debug messages that are only logged when settings.DEBUG is set."""
    caplog.set_level(logging.DEBUG, logger=gvars.log.name)

    def _messages():
        return [r.getMessage() for r in caplog.records if r.levelno == logging.DEBUG]

    return _messages


class StubMethod(getmac.Method):
    platforms = {"linux"}
    method_type = "iface"

    def test(self) -> bool:
        return True

    def get(self, arg: str) -> str:  # noqa: ARG002
        return MAC


class StubUnavailableMethod(StubMethod):
    def test(self) -> bool:
        return False


class StubFallbackMethod(StubMethod):
    pass


def test_initialize_method_cache(mocker, debug_logs):
    mocker.patch.object(consts, "PLATFORM", "linux")
    mocker.patch("getmac.getmac.METHODS", [StubUnavailableMethod, StubMethod, StubFallbackMethod])

    assert getmac.initialize_method_cache("iface")
    assert type(getmac.METHOD_CACHE["iface"]) is StubMethod
    assert [type(m) for m in getmac.FALLBACK_CACHE["iface"]] == [StubFallbackMethod]

    # Already initialized
    assert getmac.initialize_method_cache("iface")

    messages = debug_logs()
    assert not any("methods available" in m for m in messages)
    assert not any("Test failed for method" in m for m in messages)
    assert not any("Current method cache" in m for m in messages)
    assert not any("already initialized" in m for m in messages)


def test_get_by_method(mocker, debug_logs):
    mocker.patch.object(consts, "PLATFORM", "linux")
    mocker.patch("getmac.getmac.METHODS", [StubMethod])

    assert getmac.get_by_method("iface", "eth0") == MAC
    assert not any("Attempting get()" in m for m in debug_logs())


def test_remove_unusable_method_not_in_caches():
    """A method that isn't in either cache leaves the caches alone."""
    cached, fallback, other = StubMethod(), StubFallbackMethod(), StubMethod()
    getmac.METHOD_CACHE["iface"] = cached
    getmac.FALLBACK_CACHE["iface"] = [fallback]

    assert getmac._remove_unusable(other, "iface") is cached
    assert getmac.METHOD_CACHE["iface"] is cached
    assert getmac.FALLBACK_CACHE["iface"] == [fallback]


def test_get_mac_address_hostname_not_resolved(mocker, debug_logs):
    mocker.patch("socket.gethostbyname", side_effect=OSError("Name or service not known"))

    assert getmac.get_mac_address(hostname="bogus") is None
    assert not any("Traceback" in m for m in debug_logs())


def test_get_mac_address_ip_udp_packet_error(mocker, get_sample, mock_socket, debug_logs):
    getmac.METHOD_CACHE["ip4"] = getmac.ArpFile()
    arp_table = get_sample("ubuntu_18.04/cat_proc-net-arp.out")
    empty_arp_table = arp_table.splitlines(keepends=True)[0]
    mocker.patch("getmac.utils.read_file", side_effect=[empty_arp_table, arp_table])
    mock_socket.return_value.sendto.side_effect = OSError(101, "Network is unreachable")

    assert getmac.get_mac_address(ip="192.168.16.2") == "00:50:56:f1:4c:50"
    mock_socket.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
    mock_socket.return_value.close.assert_called_once_with()

    messages = debug_logs()
    assert not any("Attempting to populate ARP table" in m for m in messages)
    assert not any("Traceback" in m for m in messages)
    assert not any("getmac took" in m for m in messages)


def test_get_mac_address_ip_arp_request(mocker, get_sample, mock_socket, debug_logs):
    getmac.METHOD_CACHE["ip4"] = getmac.ArpingHost()
    mocker.patch(
        "getmac.utils.read_file", return_value=get_sample("ubuntu_18.04/cat_proc-net-arp.out")
    )
    mocker.patch.object(getmac.ArpingHost, "get", return_value=MAC)

    assert getmac.get_mac_address(ip="192.0.2.10") == MAC
    mock_socket.assert_not_called()
    assert not any("Not sending UDP packet" in m for m in debug_logs())


def test_arpfile_incomplete_entry(mocker, get_sample, debug_logs):
    mocker.patch(
        "getmac.utils.read_file", return_value=get_sample("ubuntu_20.04/cat_proc-net-arp.out")
    )

    assert getmac.ArpFile().get("192.168.0.46") is None
    assert not any("ignoring entry" in m for m in debug_logs())


def test_arp_various_args_fallback_args(mocker, get_sample, debug_logs):
    """
    "arp <ip>" fails, so "arp -an" is used, which doesn't take the IP
    as an argument. The arguments that worked are reused for the next lookup.
    """
    content = get_sample("ubuntu_18.04/arp_-an.out")
    cpe = CalledProcessError(cmd="arp", returncode=1)
    mocker.patch("getmac.utils.popen", side_effect=[cpe, content, content])

    inst = getmac.ArpVariousArgs()
    assert inst.get("192.168.16.2") == "00:50:56:f1:4c:50"
    assert inst.get("192.168.16.2") == "00:50:56:f1:4c:50"
    assert utils.popen.call_args_list == [
        mocker.call("arp", " 192.168.16.2"),
        mocker.call("arp", "-an"),
        mocker.call("arp", "-an"),
    ]
    assert not any("pair test failed" in m for m in debug_logs())


def test_arping_host_habets_fallback(mocker, get_sample, debug_logs):
    cpe = CalledProcessError(
        cmd="arping -f -c 1 192.168.16.254",
        returncode=1,
        output=get_sample("WSL2_kali_2023.1/habets_arping_-f_-c_1_172-29-16-1.out").encode(),
    )
    habets_output = get_sample("ubuntu_18.04/arping-habets.out")
    mocker.patch("getmac.utils.popen", side_effect=[cpe, habets_output])

    ap = getmac.ArpingHost()
    assert ap.get("192.168.16.254") == "00:50:56:e8:32:3c"
    assert ap._is_iputils is False
    assert not any("Falling back to Habets" in m for m in debug_logs())


def test_ifconfigother_fallback_args(mocker, get_sample, debug_logs):
    content = get_sample("third_party/facter/ifconfig/centos_5_5")
    cpe = CalledProcessError(cmd="ifconfig", returncode=1)
    mocker.patch("getmac.utils.popen", side_effect=[cpe, content])

    assert getmac.IfconfigOther().get("eth0") == "16:8D:2A:15:17:91"
    assert not any("pair test failed" in m for m in debug_logs())


@pytest.mark.parametrize(
    "data",
    [
        None,
        # No default route
        "Iface\tDestination\tGateway\nens33\t0010A8C0\t00000000\n",
    ],
)
def test_defaultifacelinuxroutefile_not_found(mocker, caplog, debug_logs, data):
    mocker.patch("getmac.utils.read_file", return_value=data)

    assert getmac.DefaultIfaceLinuxRouteFile().get() is None
    assert not debug_logs()
    assert "No data from" not in caplog.text


def test_defaultifaceiproute_no_output(mocker, debug_logs):
    mocker.patch("getmac.utils.popen", return_value="")

    assert getmac.DefaultIfaceIpRoute().get() is None
    assert not any("no output" in m for m in debug_logs())


def test_search_no_text(debug_logs):
    assert utils.search(r"(\w+)", "") is None
    assert not debug_logs()


def test_popen_and_call_proc(mocker, debug_logs):
    mocker.patch.object(gvars, "PATH", [])
    mocker.patch("subprocess.check_output", return_value=b"output")

    assert utils.popen("testcmd", "ARGS") == "output"

    messages = debug_logs()
    assert not any("Running:" in m for m in messages)
    assert not any("Output from" in m for m in messages)
