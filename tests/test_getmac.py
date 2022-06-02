# -*- coding: utf-8 -*-

import inspect
import sys
from subprocess import CalledProcessError

import pytest

from getmac import get_mac_address, getmac

PY2 = sys.version_info[0] == 2
MAC_RE_COLON = r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"


def test_all_methods_defined_are_in_methods_list():
    """Test that all methods present in getmac.py are in the METHODS list."""

    def _is_method(member):
        return (
            inspect.isclass(member)
            and issubclass(member, getmac.Method)
            and member is not getmac.Method
        )

    members = [m[1] for m in inspect.getmembers(getmac, _is_method)]
    assert set(members) == set(getmac.METHODS)
    assert len(members) == len(getmac.METHODS)


def test_method_platform_strings_are_valid():
    """test "platforms" for all methods have a valid platform name."""
    for method in getmac.METHODS:
        assert method.platforms <= getmac.Method.VALID_PLATFORM_NAMES


def test_check_path():
    assert getmac.check_path(__file__)


def test_clean_mac():
    assert getmac._clean_mac(None) is None
    assert getmac._clean_mac("") is None
    assert getmac._clean_mac("00:00:00:00:00:00:00:00:00") is None
    assert getmac._clean_mac("00:0000:0000") is None
    assert getmac._clean_mac("00000000000000000") is None
    assert getmac._clean_mac("  00-50-56-C0-00-01  ") == "00:50:56:c0:00:01"
    assert getmac._clean_mac("000000000000") == "00:00:00:00:00:00"


def test_search(get_sample):
    text = get_sample("ifconfig.out")
    regex = r"HWaddr " + MAC_RE_COLON
    assert getmac._search(regex, "") is None
    assert getmac._search(regex, text, 0) == "74:d4:35:e9:45:71"


def test_popen(mocker):
    mocker.patch("getmac.getmac.PATH", [])
    m = mocker.patch("getmac.getmac._call_proc", return_value="SUCCESS")
    assert getmac._popen("TESTCMD", "ARGS") == "SUCCESS"
    m.assert_called_once_with("TESTCMD", "ARGS")


def test_call_proc(mocker):
    mocker.patch("getmac.getmac.DEVNULL", "DEVNULL")
    mocker.patch("getmac.getmac.ENV", "ENV")

    mocker.patch("getmac.getmac.WINDOWS", True)
    m = mocker.patch("getmac.getmac.check_output", return_value="WINSUCCESS")
    assert getmac._call_proc("CMD", "arg") == "WINSUCCESS"
    m.assert_called_once_with("CMD" + " " + "arg", stderr="DEVNULL", env="ENV")

    mocker.patch("getmac.getmac.WINDOWS", False)
    m = mocker.patch("getmac.getmac.check_output", return_value="YAY")
    assert getmac._call_proc("CMD", "arg1 arg2") == "YAY"
    m.assert_called_once_with(["CMD", "arg1", "arg2"], stderr="DEVNULL", env="ENV")


def test_uuid_convert():
    assert getmac._uuid_convert(2482700837424) == "02:42:0C:80:62:30"
    assert getmac._uuid_convert(278094213753144) == "FC:EC:DA:D3:29:38"


def test_read_file_return(mocker, get_sample):
    data = get_sample("ifconfig.out")
    mock_open = mocker.mock_open(read_data=data)
    if PY2:
        mocker.patch("__builtin__.open", mock_open)
    else:
        mocker.patch("builtins.open", mock_open)
    assert getmac._read_file("ifconfig.out") == data
    mock_open.assert_called_once_with("ifconfig.out")


def test_read_file_not_exist():
    assert getmac._read_file("DOESNOTEXIST") is None


def test_fetch_ip_using_dns(mocker):
    m = mocker.patch("socket.socket")
    m.return_value.getsockname.return_value = ("1.2.3.4", 51327)
    assert getmac._fetch_ip_using_dns() == "1.2.3.4"


def test_get_method_by_name():
    assert not getmac.get_method_by_name("")
    assert not getmac.get_method_by_name("invalidmethodname")
    assert getmac.get_method_by_name("ArpFile") == getmac.ArpFile
    assert getmac.get_method_by_name("getmacexe") == getmac.GetmacExe


def test_swap_method_fallback(mocker):
    mocker.patch("getmac.getmac.METHOD_CACHE", {"ip4": getmac.ArpExe()})
    mocker.patch("getmac.getmac.FALLBACK_CACHE", {"ip4": [getmac.CtypesHost()]})
    assert getmac._swap_method_fallback("ip4", "ArpExe")
    assert not getmac._swap_method_fallback("ip4", "InvalidMethod")
    assert getmac._swap_method_fallback("ip4", "CtypesHost")
    assert isinstance(getmac.METHOD_CACHE["ip4"], getmac.Method)
    assert str(getmac.METHOD_CACHE["ip4"]) == "CtypesHost"
    assert isinstance(getmac.FALLBACK_CACHE["ip4"][0], getmac.Method)
    assert str(getmac.FALLBACK_CACHE["ip4"][0]) == "ArpExe"


@pytest.mark.parametrize("method_type", ["ip4", "ip6", "iface", "default_iface"])
def test_initialize_method_cache_valid_types(mocker, method_type):
    mocker.patch(
        "getmac.getmac.METHOD_CACHE",
        {"ip4": None, "ip6": None, "iface": None, "default_iface": None},
    )
    mocker.patch("getmac.getmac.FALLBACK_CACHE", {})
    mocker.patch("getmac.getmac.PLATFORM", "linux")
    assert getmac.initialize_method_cache(method_type)
    assert getmac.METHOD_CACHE[method_type] is not None
    if method_type in ["ip4", "ip6"]:
        assert getmac.FALLBACK_CACHE[method_type]


def test_initialize_method_cache_initialized(mocker):
    mocker.patch(
        "getmac.getmac.METHOD_CACHE",
        {"ip4": getmac.ArpFile(), "ip6": None, "iface": None, "default_iface": None},
    )
    mocker.patch("getmac.getmac.FALLBACK_CACHE", {})
    mocker.patch("getmac.getmac.PLATFORM", "linux")
    assert getmac.initialize_method_cache("ip4")
    assert str(getmac.METHOD_CACHE["ip4"]) == "ArpFile"
    assert isinstance(getmac.METHOD_CACHE["ip4"], getmac.Method)


def test_initialize_method_cache_bad_type(mocker):
    mocker.patch(
        "getmac.getmac.METHOD_CACHE",
        {"ip4": None, "ip6": None, "iface": None, "default_iface": None},
    )
    mocker.patch("getmac.getmac.FALLBACK_CACHE", {})
    mocker.patch("getmac.getmac.PLATFORM", "linux")
    with pytest.warns(RuntimeWarning):
        assert not getmac.initialize_method_cache("invalid_method_type")
    with pytest.warns(RuntimeWarning):
        assert not getmac.initialize_method_cache("ip")


def test_initialize_method_cache_platform_override(mocker):
    mocker.patch("getmac.getmac.METHODS", [getmac.GetmacExe, getmac.IfconfigEther])
    mocker.patch(
        "getmac.getmac.METHOD_CACHE",
        {"ip4": None, "ip6": None, "iface": None, "default_iface": None},
    )
    mocker.patch("getmac.getmac.FALLBACK_CACHE", {})
    mocker.patch("getmac.getmac.PLATFORM", "windows")
    mocker.patch("getmac.getmac.OVERRIDE_PLATFORM", "darwin")
    mocker.patch("getmac.getmac.check_command", return_value=True)
    assert getmac.initialize_method_cache("iface")
    assert getmac.OVERRIDE_PLATFORM == "darwin"
    assert getmac.PLATFORM == "windows"
    assert isinstance(getmac.METHOD_CACHE["iface"], getmac.IfconfigEther)


def test_initialize_method_cache_no_network_request(mocker):
    mocker.patch(
        "getmac.getmac.METHOD_CACHE",
        {"ip4": None, "ip6": None, "iface": None, "default_iface": None},
    )
    mocker.patch("getmac.getmac.FALLBACK_CACHE", {})
    mocker.patch("getmac.getmac.PLATFORM", "linux")
    mocker.patch("getmac.getmac.check_command", return_value=True)
    mocker.patch("getmac.getmac.check_path", return_value=True)
    assert getmac.initialize_method_cache("ip4", network_request=False)
    assert getmac.PLATFORM == "linux"
    assert isinstance(getmac.METHOD_CACHE["ip4"], getmac.ArpFile)


# TODO (rewrite): unit tests for get_by_method() directly
# TODO (rewrite): unit tests for FORCE_METHOD
# def test_get_by_method_force_method(mocker):
#     pass


def test_get_mac_address_localhost():
    assert get_mac_address(hostname="localhost") == "00:00:00:00:00:00"
    assert get_mac_address(ip="127.0.0.1") == "00:00:00:00:00:00"
    result = get_mac_address(hostname="localhost", network_request=False)
    assert result == "00:00:00:00:00:00"


def test_get_mac_address_interface(mocker):
    pass  # TODO (rewrite)


def test_get_mac_address_ip(mocker):
    mocker.patch("getmac.getmac.get_by_method", return_value="00:01:02:04:00:12")
    assert getmac.get_mac_address(ip="192.0.2.2") == "00:01:02:04:00:12"
    getmac.get_by_method.assert_called_once_with("ip4", "192.0.2.2")


def test_get_mac_address_ip6(mocker):
    mocker.patch("socket.has_ipv6", False)
    assert getmac.get_mac_address(ip6="fe80::1") is None

    mocker.patch("socket.has_ipv6", True)
    assert getmac.get_mac_address(ip6="192.168.0.1") is None

    mocker.patch("getmac.getmac.get_by_method", return_value="00:01:02:04:00:00")
    assert getmac.get_mac_address(ip6="fe80::1") == "00:01:02:04:00:00"
    getmac.get_by_method.assert_called_once_with("ip6", "fe80::1")


def test_get_mac_address_hostname(mocker):
    cpe = CalledProcessError(cmd="socket.gaierror", returncode=1)
    mocker.patch("socket.gethostbyname", side_effect=cpe)
    assert getmac.get_mac_address(hostname="bogus") is None

    mocker.patch("socket.gethostbyname", return_value="192.0.2.22")
    mocker.patch("getmac.getmac.get_by_method", return_value="00:01:02:04:00:22")
    assert getmac.get_mac_address(hostname="test_hostname") == "00:01:02:04:00:22"
    getmac.get_by_method.assert_called_once_with("ip4", "192.0.2.22")


def test_get_mac_address_network_request(mocker):
    pass  # TODO (rewrite)
