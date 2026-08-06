import inspect
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
)
from subprocess import CalledProcessError

import pytest

from getmac import get_mac_address, getmac, utils
from getmac.variables import consts, gvars, settings


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


def test_popen(mocker):
    mocker.patch.object(gvars, "PATH", [])
    m = mocker.patch("getmac.utils.call_proc", return_value="SUCCESS")
    assert utils.popen("TESTCMD", "ARGS") == "SUCCESS"
    m.assert_called_once_with("TESTCMD", "ARGS")


def test_get_method_by_name():
    assert not getmac.get_method_by_name("")
    assert not getmac.get_method_by_name("invalidmethodname")
    assert getmac.get_method_by_name("ArpFile") == getmac.ArpFile
    assert getmac.get_method_by_name("getmacexe") == getmac.GetmacExe


def test_get_instance_from_cache(mocker):
    with pytest.raises(KeyError):
        getmac.get_instance_from_cache("", "")

    inst = getmac.ArpFile()
    mocker.patch("getmac.getmac.METHOD_CACHE", {"ip4": inst})
    assert getmac.get_instance_from_cache("ip4", "ArpFile") is inst

    mocker.patch("getmac.getmac.METHOD_CACHE", {"ip4": None})
    assert getmac.get_instance_from_cache("ip4", "ArpFile") is None


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
    # The fallback-cache assertion below expects more than one usable Method,
    # which otherwise depends on which optional platform commands (arp,
    # arping, ...) happen to be installed on the machine running the suite.
    mocker.patch("getmac.utils.check_command", return_value=True)

    assert getmac.initialize_method_cache(method_type)
    assert getmac.METHOD_CACHE[method_type] is not None

    if method_type in ["ip4", "ip6"] and consts.PLATFORM == "linux":
        assert getmac.FALLBACK_CACHE[method_type]


def test_initialize_method_cache_initialized(mocker):
    mocker.patch(
        "getmac.getmac.METHOD_CACHE",
        {
            "ip4": getmac.ArpFile(),
            "ip6": None,
            "iface": None,
            "default_iface": None,
        },
    )
    mocker.patch("getmac.getmac.FALLBACK_CACHE", {})
    mocker.patch.object(consts, "PLATFORM", "linux")

    assert getmac.initialize_method_cache("ip4")
    assert str(getmac.METHOD_CACHE["ip4"]) == "ArpFile"
    assert isinstance(getmac.METHOD_CACHE["ip4"], getmac.Method)


def test_initialize_method_cache_bad_type(mocker):
    mocker.patch(
        "getmac.getmac.METHOD_CACHE",
        {"ip4": None, "ip6": None, "iface": None, "default_iface": None},
    )
    mocker.patch("getmac.getmac.FALLBACK_CACHE", {})
    mocker.patch.object(consts, "PLATFORM", "linux")

    with pytest.raises(RuntimeError):
        getmac.initialize_method_cache("invalid_method_type")
    with pytest.raises(RuntimeError):
        getmac.initialize_method_cache("ip")


def test_initialize_method_cache_platform_override(mocker):
    mocker.patch("getmac.getmac.METHODS", [getmac.GetmacExe, getmac.IfconfigEther])
    mocker.patch(
        "getmac.getmac.METHOD_CACHE",
        {"ip4": None, "ip6": None, "iface": None, "default_iface": None},
    )
    mocker.patch("getmac.getmac.FALLBACK_CACHE", {})
    mocker.patch.object(consts, "PLATFORM", "windows")
    mocker.patch.object(settings, "OVERRIDE_PLATFORM", "darwin")
    mocker.patch("getmac.utils.check_command", return_value=True)

    assert getmac.initialize_method_cache("iface")
    assert settings.OVERRIDE_PLATFORM == "darwin"
    assert consts.PLATFORM == "windows"
    assert isinstance(getmac.METHOD_CACHE["iface"], getmac.IfconfigEther)


def test_initialize_method_cache_no_network_request(mocker):
    mocker.patch(
        "getmac.getmac.METHOD_CACHE",
        {"ip4": None, "ip6": None, "iface": None, "default_iface": None},
    )
    mocker.patch("getmac.getmac.FALLBACK_CACHE", {})
    mocker.patch.object(consts, "PLATFORM", "linux")
    mocker.patch("getmac.utils.check_command", return_value=True)
    mocker.patch("getmac.utils.check_path", return_value=True)

    assert getmac.initialize_method_cache("ip4", network_request=False)
    assert consts.PLATFORM == "linux"
    assert isinstance(getmac.METHOD_CACHE["ip4"], getmac.ArpFile)


def test_get_by_method(mocker, get_sample):
    mocker.patch(
        "getmac.getmac.METHOD_CACHE",
        {
            "ip4": getmac.ArpExe(),
            "ip6": getmac.IpNeighborShow(),
            "iface": getmac.WmicExe(),
            "default_iface": getmac.DefaultIfaceOpenBsd(),
        },
    )

    # ip4
    content = get_sample("windows_10/arp_-a_10.0.0.175.out")
    mocker.patch("getmac.utils.popen", return_value=content)
    assert getmac.get_by_method("ip4", "10.0.0.175") == "78-28-ca-c4-66-fe"

    # ip6
    content = get_sample("android_9/ip_neighbor.out")
    mocker.patch("getmac.utils.popen", return_value=content)
    assert getmac.get_by_method("ip6", "fe80::8c8f:aaff:fec9:d28b") == "8e:8f:aa:c9:d2:8b"

    # iface
    content = get_sample("windows_10/wmic_nic.out")
    mocker.patch("getmac.utils.popen", return_value=content)
    assert getmac.get_by_method("iface", "Ethernet 3") == "00:FF:17:15:F8:C8"

    # default_iface
    content = get_sample("openbsd_6/route_nq_show_inet_gateway_priority_1.out")
    mocker.patch("getmac.utils.popen", return_value=content)
    assert getmac.get_by_method("default_iface") == "em0"


def test_get_by_method_errors(mocker):
    assert getmac.get_by_method("iface", arg="") is None

    mocker.patch(
        "getmac.getmac.METHOD_CACHE",
        {"ip4": None, "ip6": None, "iface": None, "default_iface": None},
    )
    mocker.patch("getmac.getmac.initialize_method_cache", return_value=False)
    assert getmac.get_by_method("iface", arg="ens33") is None

    mocker.patch("getmac.getmac.initialize_method_cache", return_value=True)
    assert getmac.get_by_method("iface", arg="ens33") is None

    mocker.patch(
        "getmac.getmac.METHOD_CACHE",
        {
            "ip4": None,
            "ip6": None,
            "iface": getmac.SysIfaceFile(),
            "default_iface": None,
        },
    )
    mocker.patch("getmac.utils.read_file", return_value="")
    mocker.patch.object(settings, "DEBUG", 1)
    assert getmac.get_by_method("iface", arg="ens33") is None


def test_get_by_method_force_method(mocker):
    mocker.patch.object(settings, "FORCE_METHOD", "testing123")
    assert getmac.get_by_method("iface", arg="some_arg") is None

    mocker.patch("getmac.utils.read_file", return_value="00:0c:29:b5:72:37\n")
    mocker.patch.object(settings, "FORCE_METHOD", "SysIfaceFile")
    assert getmac.get_by_method("iface", "ens33") == "00:0c:29:b5:72:37\n"


def test_get_mac_address_force_method(mocker):
    mocker.patch("getmac.utils.read_file", return_value="00:0c:29:b5:72:37\n")
    mocker.patch.object(settings, "FORCE_METHOD", "SysIfaceFile")
    assert getmac.get_mac_address(interface="ens33") == "00:0c:29:b5:72:37"


def test_get_mac_address_localhost():
    assert get_mac_address(hostname="localhost") == "00:00:00:00:00:00"
    assert get_mac_address(hostname=b"localhost") == "00:00:00:00:00:00"
    assert get_mac_address(ip="127.0.0.1") == "00:00:00:00:00:00"
    assert get_mac_address(ip=b"127.0.0.1") == "00:00:00:00:00:00"

    result = get_mac_address(hostname="localhost", network_request=False)
    assert result == "00:00:00:00:00:00"


def test_get_mac_address_interface(mocker):
    mocker.patch("getmac.getmac.get_by_method", return_value="00:0c:29:b5:72:37")
    assert getmac.get_mac_address(interface="ens33") == "00:0c:29:b5:72:37"
    getmac.get_by_method.assert_called_once_with("iface", "ens33")

    # bytes
    assert getmac.get_mac_address(interface=b"ens33") == "00:0c:29:b5:72:37"


def test_get_mac_address_ip(mocker):
    mocker.patch("getmac.getmac.get_by_method", return_value="00:01:02:04:00:12")
    assert getmac.get_mac_address(ip="192.0.2.2") == "00:01:02:04:00:12"
    getmac.get_by_method.assert_called_once_with("ip4", "192.0.2.2")

    # bytes
    assert getmac.get_mac_address(ip=b"192.0.2.2") == "00:01:02:04:00:12"

    # IPv4Address
    mocker.patch("getmac.getmac.get_by_method", return_value="00:01:02:04:00:55")
    assert getmac.get_mac_address(ip=IPv4Address("192.0.2.55")) == "00:01:02:04:00:55"
    getmac.get_by_method.assert_called_once_with("ip4", "192.0.2.55")

    # IPv4Interface
    mocker.patch("getmac.getmac.get_by_method", return_value="00:01:02:04:00:66")
    assert getmac.get_mac_address(ip=IPv4Interface("192.0.2.66/24")) == "00:01:02:04:00:66"
    getmac.get_by_method.assert_called_once_with("ip4", "192.0.2.66")

    # IPv6Address
    mocker.patch("getmac.getmac.get_by_method", return_value="00:01:02:04:00:33")
    assert getmac.get_mac_address(ip=IPv6Address("fe80::33")) == "00:01:02:04:00:33"
    getmac.get_by_method.assert_called_once_with("ip6", "fe80::33")

    # IPv6Interface
    mocker.patch("getmac.getmac.get_by_method", return_value="00:01:02:04:00:44")
    assert getmac.get_mac_address(ip=IPv6Interface("fe80::44/24")) == "00:01:02:04:00:44"
    getmac.get_by_method.assert_called_once_with("ip6", "fe80::44")


def test_get_mac_address_ip6(mocker):
    mocker.patch("socket.has_ipv6", False)
    assert getmac.get_mac_address(ip6="fe80::1") is None

    mocker.patch("socket.has_ipv6", True)
    assert getmac.get_mac_address(ip6="192.168.0.1") is None

    mocker.patch("getmac.getmac.get_by_method", return_value="00:01:02:04:00:00")
    assert getmac.get_mac_address(ip6="fe80::1") == "00:01:02:04:00:00"
    getmac.get_by_method.assert_called_once_with("ip6", "fe80::1")

    # bytes
    assert getmac.get_mac_address(ip6=b"fe80::1") == "00:01:02:04:00:00"

    # IPv6Address
    mocker.patch("getmac.getmac.get_by_method", return_value="00:01:02:04:00:11")
    assert getmac.get_mac_address(ip6=IPv6Address("fe80::11")) == "00:01:02:04:00:11"
    getmac.get_by_method.assert_called_once_with("ip6", "fe80::11")

    # IPv6Interface
    mocker.patch("getmac.getmac.get_by_method", return_value="00:01:02:04:00:22")
    assert getmac.get_mac_address(ip6=IPv6Interface("fe80::22/24")) == "00:01:02:04:00:22"
    getmac.get_by_method.assert_called_once_with("ip6", "fe80::22")


def test_get_mac_address_hostname(mocker):
    cpe = CalledProcessError(cmd="socket.gaierror", returncode=1)
    mocker.patch("socket.gethostbyname", side_effect=cpe)
    assert getmac.get_mac_address(hostname="bogus") is None

    mocker.patch("socket.gethostbyname", return_value="192.0.2.22")
    mocker.patch("getmac.getmac.get_by_method", return_value="00:01:02:04:00:22")
    assert getmac.get_mac_address(hostname="test_hostname") == "00:01:02:04:00:22"
    getmac.get_by_method.assert_called_once_with("ip4", "192.0.2.22")

    # bytes
    assert getmac.get_mac_address(hostname=b"test_hostname") == "00:01:02:04:00:22"


def test_get_mac_address_default_args_windows_net_request_true(mocker):
    mocker.patch.object(consts, "WINDOWS", True)
    mocker.patch("getmac.getmac.get_by_method", return_value="00:FF:17:15:F8:C8")
    assert getmac.get_mac_address(network_request=False) == "00:ff:17:15:f8:c8"
    getmac.get_by_method.assert_called_once_with("iface", "Ethernet")

    mocker.patch("getmac.getmac.get_by_method", return_value="78:28:ca:c4:66:fe")
    mocker.patch("getmac.utils.fetch_ip_using_dns", return_value="10.0.0.175")
    assert getmac.get_mac_address(network_request=True) == "78:28:ca:c4:66:fe"
    getmac.get_by_method.assert_called_once_with("ip4", "10.0.0.175")


def test_get_mac_address_default_args_fallback_global(mocker):
    mocker.patch.object(consts, "WINDOWS", False)
    mocker.patch.object(gvars, "DEFAULT_IFACE", "eth0")
    mocker.patch("getmac.getmac.get_by_method", return_value="08:00:27:e8:81:6f")
    assert getmac.get_mac_address() == "08:00:27:e8:81:6f"
    getmac.get_by_method.assert_called_once_with("iface", "eth0")


def test_get_mac_address_invalid_types():
    """
    Test that invalid types for 'ip' and 'ip6' arguments raise ValueError.
    """

    with pytest.raises(ValueError, match="IPv4Network"):
        getmac.get_mac_address(ip=IPv4Network("192.0.1.0/24"))

    with pytest.raises(ValueError, match="IPv6Network"):
        getmac.get_mac_address(ip=IPv6Network("2001:db00::0/24"))

    with pytest.raises(ValueError, match="IPv6Network"):
        getmac.get_mac_address(ip6=IPv6Network("2001:db00::0/24"))

    with pytest.raises(ValueError, match="Unknown type for 'ip' argument"):
        getmac.get_mac_address(ip=object())

    with pytest.raises(ValueError, match="Unknown type for 'ip6' argument"):
        getmac.get_mac_address(ip6=object())


def test_get_mac_address_default_interface(mocker):
    """
    Test default interface is used when no other arguments are given.
    """
    # need to mock get_by_method called with:
    #   "default_iface" => test_iface
    #   "iface", "test_iface" => MAC address
    comp_mac = "00:11:22:33:44:55"

    def __test_iface_default(a1, a2=None):  # noqa: ARG001
        if a1 == "default_iface":
            return "test_iface"
        return comp_mac

    mocker.patch.object(consts, "WINDOWS", False)
    mocker.patch.object(gvars, "DEFAULT_IFACE", "")
    mocker.patch(
        "getmac.getmac.get_by_method",
        side_effect=__test_iface_default,
    )
    assert getmac.get_mac_address() == comp_mac


def test_get_mac_address_default_interface_fallback(mocker):
    """
    More coverage of the fallback logic if default interface can't be determined.
    """
    mocker.patch.object(consts, "WINDOWS", False)
    comp_mac = "00:11:22:33:44:44"

    def __test_iface_fallback(a1, a2=None):  # noqa: ARG001
        if a1 == "default_iface":
            return ""
        return comp_mac

    # BSD fallback path
    mocker.patch.object(consts, "BSD", True)
    mocker.patch.object(gvars, "DEFAULT_IFACE", "")
    mocker.patch(
        "getmac.getmac.get_by_method",
        side_effect=__test_iface_fallback,
    )
    assert getmac.get_mac_address() == comp_mac
    assert gvars.DEFAULT_IFACE == "em0"

    # Darwin fallback path
    mocker.patch.object(consts, "BSD", False)
    mocker.patch.object(consts, "DARWIN", True)
    mocker.patch.object(gvars, "DEFAULT_IFACE", "")
    mocker.patch(
        "getmac.getmac.get_by_method",
        side_effect=__test_iface_fallback,
    )
    assert getmac.get_mac_address() == comp_mac
    assert gvars.DEFAULT_IFACE == "en0"

    # HPUX fallback path
    mocker.patch.object(consts, "DARWIN", False)
    mocker.patch.object(consts, "HPUX", True)
    mocker.patch.object(gvars, "DEFAULT_IFACE", "")
    mocker.patch(
        "getmac.getmac.get_by_method",
        side_effect=__test_iface_fallback,
    )
    assert getmac.get_mac_address() == comp_mac
    assert gvars.DEFAULT_IFACE == "lan0"

    # eth0 fallback path
    mocker.patch.object(consts, "HPUX", False)
    mocker.patch.object(gvars, "DEFAULT_IFACE", "")
    mocker.patch(
        "getmac.getmac.get_by_method",
        side_effect=__test_iface_fallback,
    )
    assert getmac.get_mac_address() == comp_mac
    assert gvars.DEFAULT_IFACE == "eth0"

    # test hack to fallback to loopback
    mocker.patch.object(gvars, "DEFAULT_IFACE", "")
    mocker.patch(
        "getmac.getmac.get_by_method",
        side_effect=lambda a1, a2=None: "00:11:22:33:44:04" if a2 == "lo" else "",  # noqa: ARG005
    )
    assert getmac.get_mac_address() == "00:11:22:33:44:04"


def test_get_default_interface(mocker, get_sample):
    mocker.patch(
        "getmac.getmac.METHOD_CACHE",
        {
            "default_iface": getmac.DefaultIfaceOpenBsd(),
        },
    )

    content = get_sample("openbsd_6/route_nq_show_inet_gateway_priority_1.out")
    mocker.patch("getmac.utils.popen", return_value=content)
    assert getmac.get_default_interface() == "em0"
