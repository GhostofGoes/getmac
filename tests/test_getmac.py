import inspect
import socket
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

MAC = "00:11:22:33:44:55"


@pytest.fixture(autouse=True)
def _empty_caches(mocker):
    """
    Start every test with empty method caches and no default interface, so tests
    don't depend on what a previous test (or the machine running the tests) cached.
    Tests can put methods in the caches directly, the original caches are restored.
    """
    mocker.patch("getmac.getmac.METHOD_CACHE", dict.fromkeys(getmac.METHOD_CACHE))
    mocker.patch("getmac.getmac.FALLBACK_CACHE", {k: [] for k in getmac.FALLBACK_CACHE})
    mocker.patch.object(gvars, "DEFAULT_IFACE", "")


@pytest.fixture(autouse=True)
def mock_socket(mocker):
    """Don't send the UDP packet used to populate the ARP table onto the network."""
    return mocker.patch("socket.socket")


class StubMethod(getmac.Method):
    """Stands in for a real method, without running commands or reading files."""

    platforms = {"linux"}
    method_type = "iface"

    def test(self) -> bool:
        return True

    def get(self, arg: str) -> str:  # noqa: ARG002
        return MAC


class StubOtherMethod(StubMethod):
    platforms = {"other"}


class StubUnavailableMethod(StubMethod):
    def test(self) -> bool:
        return False


class StubBrokenTestMethod(StubMethod):
    def test(self) -> bool:
        raise OSError("Permission denied")


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

    # Fallback methods are checked if it isn't the cached method
    fallback_inst = getmac.ArpingHost()
    mocker.patch("getmac.getmac.METHOD_CACHE", {"ip4": inst})
    mocker.patch("getmac.getmac.FALLBACK_CACHE", {"ip4": [getmac.ArpExe(), fallback_inst]})
    assert getmac.get_instance_from_cache("ip4", "ArpingHost") is fallback_inst
    assert getmac.get_instance_from_cache("ip4", "CtypesHost") is None


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


def test_initialize_method_cache_unsupported_platform(mocker):
    """
    If there aren't any methods for the platform, the methods for
    the generic platform "other" are used instead, with a warning.
    """
    mocker.patch("getmac.getmac.METHODS", [StubMethod, StubOtherMethod])
    mocker.patch.object(consts, "PLATFORM", "fakeos")

    with pytest.warns(RuntimeWarning, match="No methods for platform 'fakeos'"):
        assert getmac.initialize_method_cache("iface")
    assert type(getmac.METHOD_CACHE["iface"]) is StubOtherMethod

    # No "other" methods either
    getmac.METHOD_CACHE["iface"] = None
    mocker.patch("getmac.getmac.METHODS", [StubMethod])
    with pytest.warns(RuntimeWarning):
        with pytest.raises(RuntimeError, match=r"No valid methods found .* platform 'fakeos'"):
            getmac.initialize_method_cache("iface")


def test_initialize_method_cache_failed_tests(mocker):
    """Methods that fail test(), or raise an exception in test(), aren't used."""
    mocker.patch.object(consts, "PLATFORM", "linux")
    mocker.patch("getmac.getmac.METHODS", [StubUnavailableMethod, StubBrokenTestMethod])

    with pytest.raises(RuntimeError, match="All 2 'iface' methods failed to test!"):
        getmac.initialize_method_cache("iface")
    assert getmac.METHOD_CACHE["iface"] is None

    mocker.patch(
        "getmac.getmac.METHODS", [StubUnavailableMethod, StubBrokenTestMethod, StubMethod]
    )
    assert getmac.initialize_method_cache("iface")
    assert type(getmac.METHOD_CACHE["iface"]) is StubMethod
    assert getmac.FALLBACK_CACHE["iface"] == []


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


@pytest.mark.parametrize(
    ("error", "falls_back"),
    [
        # Unexpected errors, e.g. the command was removed after the method was tested
        (FileNotFoundError(2, "No such file or directory"), True),
        (CalledProcessError(returncode=255, cmd="ip neighbor show 192.168.16.2"), True),
        # Exit code 1 usually means the lookup failed, not the method
        # (e.g. "ifconfig eth8" if there's no eth8), so the method is kept
        (CalledProcessError(returncode=1, cmd="ip neighbor show 192.168.16.2"), False),
    ],
)
def test_get_by_method_fallback_on_error(mocker, get_sample, error, falls_back):
    """
    If a method fails with an unexpected error, it's marked unusable,
    and the next method in the fallback cache is used instead.
    """
    ip_neighbor, arp_file = getmac.IpNeighborShow(), getmac.ArpFile()
    getmac.METHOD_CACHE["ip4"] = ip_neighbor
    getmac.FALLBACK_CACHE["ip4"] = [arp_file]
    mocker.patch("getmac.utils.popen", side_effect=error)
    mocker.patch(
        "getmac.utils.read_file", return_value=get_sample("ubuntu_18.04/cat_proc-net-arp.out")
    )

    result = getmac.get_by_method("ip4", "192.168.16.2")

    assert result == ("00:50:56:f1:4c:50" if falls_back else None)
    assert ip_neighbor.unusable is falls_back
    assert getmac.METHOD_CACHE["ip4"] is (arp_file if falls_back else ip_neighbor)
    assert getmac.FALLBACK_CACHE["ip4"] == ([] if falls_back else [arp_file])


def test_get_by_method_fallback_on_unusable(mocker, get_sample):
    """
    Methods can mark themselves unusable, e.g. ArpFile if /proc/net/arp can't
    be read, and the next method in the fallback cache is used from then on.
    """
    arp_file, ip_neighbor = getmac.ArpFile(), getmac.IpNeighborShow()
    getmac.METHOD_CACHE["ip4"] = arp_file
    getmac.FALLBACK_CACHE["ip4"] = [ip_neighbor]
    mocker.patch("getmac.utils.read_file", return_value=None)
    mocker.patch(
        "getmac.utils.popen", return_value=get_sample("ubuntu_18.04/ip_neighbor_show.out")
    )

    assert getmac.get_by_method("ip4", "192.168.16.2") == "00:50:56:f1:4c:50"
    assert arp_file.unusable is True
    assert getmac.METHOD_CACHE["ip4"] is ip_neighbor
    assert getmac.FALLBACK_CACHE["ip4"] == []

    utils.read_file.reset_mock()
    assert getmac.get_by_method("ip4", "192.168.16.254") == "00:50:56:e1:2f:51"
    utils.read_file.assert_not_called()


def test_get_by_method_no_usable_methods(mocker):
    """The lookup fails if the last usable method becomes unusable."""
    arp_file = getmac.ArpFile()
    getmac.METHOD_CACHE["ip4"] = arp_file
    mocker.patch("getmac.utils.read_file", return_value=None)

    assert getmac.get_by_method("ip4", "192.168.16.2") is None
    assert arp_file.unusable is True
    assert getmac.METHOD_CACHE["ip4"] is None

    with pytest.raises(RuntimeError, match="No usable methods found for MAC type 'ip4'"):
        getmac._attempt_method_get(arp_file, "ip4", "192.168.16.2")


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


def test_get_mac_address_ip6(mocker, mock_socket):
    mocker.patch("socket.has_ipv6", False)
    assert getmac.get_mac_address(ip6="fe80::1") is None

    mocker.patch("socket.has_ipv6", True)
    assert getmac.get_mac_address(ip6="192.168.0.1") is None

    mocker.patch("getmac.getmac.get_by_method", return_value="00:01:02:04:00:00")
    assert getmac.get_mac_address(ip6="fe80::1") == "00:01:02:04:00:00"
    getmac.get_by_method.assert_called_once_with("ip6", "fe80::1")
    # A UDP packet is sent to the host first, to populate the NDP table
    mock_socket.assert_called_once_with(socket.AF_INET6, socket.SOCK_DGRAM)
    mock_socket.return_value.sendto.assert_called_once_with(b"", ("fe80::1", settings.PORT))

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


@pytest.mark.parametrize(
    ("cached", "fallbacks", "arp_method"),
    [
        # Windows
        (getmac.CtypesHost, [], getmac.CtypesHost),
        (getmac.ArpingHost, [getmac.IpNeighborShow], getmac.ArpingHost),
        # The host isn't in /proc/net/arp, so arping is swapped in for ArpFile
        (getmac.ArpFile, [getmac.IpNeighborShow, getmac.ArpingHost], getmac.ArpingHost),
    ],
)
def test_get_mac_address_ip_arp_request(
    mocker, get_sample, mock_socket, cached, fallbacks, arp_method
):
    """
    If there's a method that sends an ARP request, it's used to look up the
    host, instead of sending a UDP packet to populate the ARP table.
    """
    getmac.METHOD_CACHE["ip4"] = cached()
    getmac.FALLBACK_CACHE["ip4"] = [fallback() for fallback in fallbacks]
    mocker.patch(
        "getmac.utils.read_file", return_value=get_sample("ubuntu_18.04/cat_proc-net-arp.out")
    )
    arp_get = mocker.patch.object(arp_method, "get", return_value=MAC)

    assert getmac.get_mac_address(ip="192.0.2.10") == MAC
    arp_get.assert_called_once_with("192.0.2.10")
    assert type(getmac.METHOD_CACHE["ip4"]) is arp_method
    mock_socket.assert_not_called()


@pytest.mark.parametrize("send_error", [None, OSError(101, "Network is unreachable")])
def test_get_mac_address_ip_udp_packet(mocker, get_sample, mock_socket, send_error):
    """
    Without a method that sends an ARP request, a UDP packet is sent to the host
    so the OS adds it to the ARP table, then the table is checked again.
    The table is still checked if the packet can't be sent.
    """
    getmac.METHOD_CACHE["ip4"] = getmac.ArpFile()
    getmac.FALLBACK_CACHE["ip4"] = [getmac.IpNeighborShow()]
    arp_table = get_sample("ubuntu_18.04/cat_proc-net-arp.out")
    # Just the header, the host is added after the packet is sent
    empty_arp_table = arp_table.splitlines(keepends=True)[0]
    mocker.patch("getmac.utils.read_file", side_effect=[empty_arp_table, arp_table])
    mocker.patch.object(settings, "PORT", 44444)
    mock_socket.return_value.sendto.side_effect = send_error

    assert getmac.get_mac_address(ip="192.168.16.2") == "00:50:56:f1:4c:50"
    mock_socket.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
    mock_socket.return_value.sendto.assert_called_once_with(b"", ("192.168.16.2", 44444))
    mock_socket.return_value.close.assert_called_once_with()


def test_get_mac_address_ip_arpfile_issue_76(mocker, get_sample, mock_socket):
    """
    get_mac_address() shouldn't return the stale MAC of an
    incomplete entry in ``/proc/net/arp`` (issue #76).
    """
    getmac.METHOD_CACHE["ip4"] = getmac.ArpFile()
    mocker.patch(
        "getmac.utils.read_file", return_value=get_sample("ubuntu_20.04/cat_proc-net-arp.out")
    )

    assert getmac.get_mac_address(ip="192.168.0.47") == "02:00:00:00:00:47"
    mock_socket.assert_not_called()

    # Not found, so a UDP packet is sent to try to populate the ARP table
    assert getmac.get_mac_address(ip="192.168.0.46") is None
    mock_socket.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)


def test_get_mac_address_ip_force_method(mocker, get_sample, mock_socket):
    """
    A forced method is used instead of ArpFile and ARP request methods,
    after sending a UDP packet to populate the ARP table.
    """
    getmac.METHOD_CACHE["ip4"] = getmac.ArpFile()
    getmac.FALLBACK_CACHE["ip4"] = [getmac.ArpingHost()]
    mocker.patch.object(settings, "FORCE_METHOD", "IpNeighborShow")
    mocker.patch("getmac.utils.read_file")
    arping_get = mocker.patch.object(getmac.ArpingHost, "get")
    mocker.patch(
        "getmac.utils.popen", return_value=get_sample("ubuntu_18.04/ip_neighbor_show.out")
    )

    assert getmac.get_mac_address(ip="192.168.16.2") == "00:50:56:f1:4c:50"
    utils.popen.assert_called_once_with("ip", "neighbor show 192.168.16.2")
    utils.read_file.assert_not_called()
    arping_get.assert_not_called()
    mock_socket.return_value.sendto.assert_called_once_with(b"", ("192.168.16.2", settings.PORT))


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


# --- Platform used to choose methods: OVERRIDE_PLATFORM and WSL1 ("wsl") ---------------
#
# How initialize_method_cache() picks methods for settings.OVERRIDE_PLATFORM and for the
# "wsl" platform (WSL1). Detecting the platform (consts.PLATFORM) is tested in
# tests/test_variables.py.


def _pass_all_method_tests(mocker):
    """Make every method's test() pass, so only the type and platform decide what's used."""
    for method in getmac.METHODS:
        mocker.patch.object(method, "test", return_value=True)


def _cached_method_names(method_type):
    """Names of the primary method and then the fallbacks, in the order they're used."""
    methods = [getmac.METHOD_CACHE[method_type], *getmac.FALLBACK_CACHE[method_type]]
    return [type(method).__name__ for method in methods]


@pytest.mark.parametrize(
    ("override", "method_type", "expected"),
    [
        # Values returned by platform.system()
        (
            "Linux",
            "default_iface",
            ["DefaultIfaceLinuxRouteFile", "DefaultIfaceIpRoute", "DefaultIfaceRouteCommand"],
        ),
        ("Windows", "iface", ["GetmacExe", "IpconfigExe", "WmicExe"]),
        ("Darwin", "iface", ["DarwinNetworksetupIface", "IfconfigEther"]),
        ("FreeBSD", "default_iface", ["DefaultIfaceRouteGetCommand", "DefaultIfaceFreeBsd"]),
        ("OpenBSD", "ip6", ["ArpOpenbsd"]),
        ("SunOS", "ip4", ["ArpVariousArgs"]),
        ("HP-UX", "iface", ["LanscanIface"]),
        # Lowercase names, other cases, and surrounding whitespace
        ("darwin", "iface", ["DarwinNetworksetupIface", "IfconfigEther"]),
        (" DARWIN\n", "iface", ["DarwinNetworksetupIface", "IfconfigEther"]),
        ("WSL", "ip4", ["ArpExe"]),
    ],
)
def test_platform_override_ignores_case_and_whitespace(
    mocker, recwarn, override, method_type, expected
):
    """
    OVERRIDE_PLATFORM accepts the values returned by platform.system(), such as "Darwin",
    in any case, like the --override-platform command-line option.
    """
    _pass_all_method_tests(mocker)
    mocker.patch.object(consts, "PLATFORM", "fakeos")
    mocker.patch.object(settings, "OVERRIDE_PLATFORM", override)

    assert getmac.initialize_method_cache(method_type)

    assert _cached_method_names(method_type) == expected
    # The override is a known platform, so there's no fallback to the "other" methods
    assert not [w for w in recwarn if issubclass(w.category, RuntimeWarning)]
    # The setting itself isn't changed
    assert settings.OVERRIDE_PLATFORM == override


def test_platform_override_logs_normalized_name(mocker, caplog):
    _pass_all_method_tests(mocker)
    mocker.patch.object(consts, "PLATFORM", "linux")
    mocker.patch.object(settings, "OVERRIDE_PLATFORM", " Darwin ")

    with caplog.at_level("WARNING", logger="getmac"):
        assert getmac.initialize_method_cache("iface")

    assert (
        "Platform override is set, using 'darwin' as platform instead of "
        "detected platform 'linux'" in caplog.messages
    )


@pytest.mark.parametrize("override", ["", " ", "\t\n"])
def test_platform_override_blank_uses_detected_platform(mocker, caplog, recwarn, override):
    """An empty or whitespace-only OVERRIDE_PLATFORM means there's no override."""
    _pass_all_method_tests(mocker)
    mocker.patch.object(consts, "PLATFORM", "darwin")
    mocker.patch.object(settings, "OVERRIDE_PLATFORM", override)

    with caplog.at_level("WARNING", logger="getmac"):
        assert getmac.initialize_method_cache("iface")

    assert _cached_method_names("iface") == ["DarwinNetworksetupIface", "IfconfigEther"]
    assert "Platform override" not in caplog.text
    assert not [w for w in recwarn if issubclass(w.category, RuntimeWarning)]


@pytest.mark.parametrize("network_request", [True, False])
@pytest.mark.parametrize(
    ("method_type", "expected"),
    [
        # Remote hosts: the Windows ARP table, with "arp.exe" (run through WSL's Windows
        # interop). The Linux methods (ArpFile, ArpingHost, IpNeighborShow, ArpVariousArgs)
        # aren't used.
        ("ip4", ["ArpExe"]),
        # Local interfaces: the Linux methods, except IfconfigOther
        (
            "iface",
            ["SysIfaceFile", "FcntlIface", "IfconfigWithIfaceArg", "IpLinkIface", "NetstatIface"],
        ),
        # Default interface: the same methods as on Linux
        (
            "default_iface",
            ["DefaultIfaceLinuxRouteFile", "DefaultIfaceIpRoute", "DefaultIfaceRouteCommand"],
        ),
    ],
)
def test_wsl1_method_selection(mocker, recwarn, method_type, expected, network_request):
    """WSL1 is detected as the "wsl" platform, which has methods of its own."""
    _pass_all_method_tests(mocker)
    mocker.patch.object(consts, "PLATFORM", "wsl")
    mocker.patch.object(settings, "OVERRIDE_PLATFORM", "")

    assert getmac.initialize_method_cache(method_type, network_request)

    assert _cached_method_names(method_type) == expected
    assert not [w for w in recwarn if issubclass(w.category, RuntimeWarning)]


def test_wsl1_ip6_falls_back_to_other_platform(mocker):
    """
    No IPv6 method lists "wsl", so WSL1 uses the "other" methods, with a warning.
    These are the same methods as on Linux.
    """
    _pass_all_method_tests(mocker)
    mocker.patch.object(consts, "PLATFORM", "wsl")
    mocker.patch.object(settings, "OVERRIDE_PLATFORM", "")

    with pytest.warns(RuntimeWarning, match="No methods for platform 'wsl'"):
        assert getmac.initialize_method_cache("ip6")

    assert _cached_method_names("ip6") == ["IpNeighborShow", "ArpVariousArgs"]


def test_wsl1_get_mac_address_ip4_uses_arp_exe(mocker, mock_socket, get_sample):
    mocker.patch.object(consts, "PLATFORM", "wsl")
    mocker.patch.object(settings, "OVERRIDE_PLATFORM", "")
    mocker.patch.object(settings, "FORCE_METHOD", "")
    mocker.patch("getmac.utils.check_command", return_value=True)
    content = get_sample("windows_10/arp_-a_10.0.0.175.out")
    mock_popen = mocker.patch("getmac.utils.popen", return_value=content)

    assert get_mac_address(ip="10.0.0.175") == "78:28:ca:c4:66:fe"

    mock_popen.assert_called_once_with("arp.exe", "-a 10.0.0.175")
    # Neither ArpingHost nor CtypesHost is used on WSL1, so a UDP packet populates the ARP table
    mock_socket.return_value.sendto.assert_called_once_with(b"", ("10.0.0.175", settings.PORT))
