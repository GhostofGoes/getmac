# -*- coding: utf-8 -*-

import platform
import socket
import sys
import uuid
from subprocess import CalledProcessError

import pytest

from getmac import getmac

# TODO: freebsd11/netstat_-ia.out
# TODO: netstat_-ian_aix.out
# TODO: netstat_-ian_unknown.out
# TODO: macos_10.12.6/netstat_-i.out
# TODO: macos_10.12.6/netstat_-ia.out


def test_darwinnetworksetupiface(benchmark, mocker, get_sample):
    content = get_sample("macos_10.12.6/networksetup_-getmacaddress_en0.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert "08:00:27:2b:c2:ed" == benchmark(
        getmac.DarwinNetworksetupIface().get, arg="en0"
    )

    mocker.patch("getmac.getmac._popen", return_value=None)
    assert not getmac.DarwinNetworksetupIface().get("en0")
    mocker.patch("getmac.getmac._popen", return_value="")
    assert not getmac.DarwinNetworksetupIface().get("en0")

    mocker.patch("getmac.getmac.check_command", return_value=True)
    assert getmac.DarwinNetworksetupIface().test() is True
    getmac.check_command.assert_called_once_with("networksetup")


ifconfigether_samples = [
    ("2c:f0:ee:2f:c7:de", "OSX/ifconfig.out"),
    ("08:00:27:2b:c2:ed", "macos_10.12.6/ifconfig.out"),
    ("08:00:27:2b:c2:ed", "macos_10.12.6/ifconfig_en0.out"),
]


@pytest.mark.parametrize(("mac", "sample_file"), ifconfigether_samples)
def test_ifconfigether_darwin(benchmark, mocker, get_sample, mac, sample_file):
    content = get_sample(sample_file)
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert mac == benchmark(getmac.IfconfigEther().get, arg="en0")

    if sample_file == "OSX/ifconfig.out":
        assert "b2:eb:94:59:0b:d4" == getmac.IfconfigEther().get("awdl0")
        assert "32:00:10:bf:60:00" == getmac.IfconfigEther().get("bridge0")

    assert not getmac.IfconfigEther().get("en")
    assert not getmac.IfconfigEther().get("lo")
    assert not getmac.IfconfigEther().get("lo0")
    assert not getmac.IfconfigEther().get("gif0")
    assert not getmac.IfconfigEther().get("stf0")
    assert not getmac.IfconfigEther().get("XHC20")
    assert not getmac.IfconfigEther().get("utun0")


# TODO: several of these should be a different method without a interface arg
ifconfig_samples = [
    ("74:d4:35:e9:45:71", "eth0", "ifconfig.out"),
    ("00:0c:29:b5:72:37", "ens33", "ubuntu_18.04/ifconfig_ens33.out"),
    ("08:00:27:e8:81:6f", "eth0", "ubuntu_12.04/ifconfig.out"),
    ("08:00:27:e8:81:6f", "eth0", "ubuntu_12.04/ifconfig_eth0.out"),
    ("00:15:5d:83:d9:0a", "eth8", "WSL_ubuntu_18.04/ifconfig_eth8.out"),
    # NOTE: the freebsd samples were taken on different machines, hence different MACs
    ("08:00:27:33:37:26", "em0", "freebsd11/ifconfig_em0.out"),
    ("08:00:27:ab:b0:67", "em0", "freebsd11/ifconfig.out"),
    ("2c:f0:ee:2f:c7:de", "en0", "OSX/ifconfig.out"),
    ("b2:eb:94:59:0b:d4", "awdl0", "OSX/ifconfig.out"),
    ("32:00:10:bf:60:00", "bridge0", "OSX/ifconfig.out"),
    ("08:00:27:18:64:56", "em0", "openbsd_6/ifconfig.out"),
    ("08:00:27:18:64:56", "em0", "openbsd_6/ifconfig_em0.out"),
]


@pytest.mark.parametrize(("mac", "iface", "sample_file"), ifconfig_samples)
def test_parse_ifconfig_samples(benchmark, get_sample, mac, iface, sample_file):
    content = get_sample(sample_file)
    assert mac == benchmark(getmac._parse_ifconfig, iface=iface, command_output=content)

    # check trailing ":" is stripped
    assert mac == getmac._parse_ifconfig(iface + ":", content)

    # Ensure no overmatches or false-positives occur
    assert not getmac._parse_ifconfig("l", content)
    assert not getmac._parse_ifconfig("lo", content)
    assert not getmac._parse_ifconfig("lo0", content)
    assert not getmac._parse_ifconfig("lo0:", content)
    assert not getmac._parse_ifconfig("ether", content)
    assert not getmac._parse_ifconfig("eth", content)
    assert not getmac._parse_ifconfig("em", content)
    assert not getmac._parse_ifconfig("e", content)
    assert not getmac._parse_ifconfig("h0", content)
    assert not getmac._parse_ifconfig("docker0", content)
    assert not getmac._parse_ifconfig("XHC20", content)
    assert not getmac._parse_ifconfig("utun0", content)
    assert not getmac._parse_ifconfig("enc0", content)
    assert not getmac._parse_ifconfig("pflog0", content)
    assert not getmac._parse_ifconfig("", content)


def test_parse_ifconfig_bad_params():
    assert not getmac._parse_ifconfig(None, None)
    assert not getmac._parse_ifconfig("", "")
    assert not getmac._parse_ifconfig("   ", "")
    assert not getmac._parse_ifconfig("   ", "        ")
    assert not getmac._parse_ifconfig("   ", "     ether   ")


@pytest.mark.parametrize(("mac", "iface", "sample_file"), ifconfig_samples)
def test_ifconfigwithifacearg_samples(mocker, get_sample, mac, iface, sample_file):
    content = get_sample(sample_file)
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert mac == getmac.IfconfigWithIfaceArg().get(iface)


def test_ifconfigwithifacearg_bad_exits(mocker):
    cpe = CalledProcessError(cmd="ifconfig", returncode=1)
    mocker.patch("getmac.getmac._popen", side_effect=cpe)
    assert getmac.IfconfigWithIfaceArg().get("eth0") is None

    cpe = CalledProcessError(cmd="ifconfig", returncode=255)
    mocker.patch("getmac.getmac._popen", side_effect=cpe)
    with pytest.raises(CalledProcessError):
        getmac.IfconfigWithIfaceArg().get("eth0")


def test_arping_host_habets(benchmark, mocker, get_sample):
    content = get_sample("ubuntu_18.04/arping-habets.out")
    mocker.patch("getmac.getmac._popen", return_value=content)

    ap = getmac.ArpingHost()
    ap._is_iputils = False
    ap.get("192.168.16.254")

    assert "00:50:56:e8:32:3c" == benchmark(ap.get, arg="192.168.16.254")


def test_arping_host_iputils(benchmark, mocker, get_sample):
    content = get_sample("ubuntu_18.04/arping-iputils.out")
    mocker.patch("getmac.getmac._popen", return_value=content)

    ap = getmac.ArpingHost()
    ap.get("192.168.16.254")

    assert "00:50:56:E8:32:3C" == benchmark(ap.get, arg="192.168.16.254")


def test_arping_host_busybox(benchmark, mocker, get_sample):
    content = get_sample("WSL2_kali_2023.1/busybox_arping_-f_-c_1_172-29-16-1.out")
    mocker.patch("getmac.getmac._popen", return_value=content)

    ap = getmac.ArpingHost()
    ap.get("172.29.16.1")

    assert "00:15:5d:20:f2:73" == benchmark(ap.get, arg="172.29.16.1")


def test_windows_10_iface_getmac_exe(benchmark, mocker, get_sample):
    content = get_sample("windows_10/getmac.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert "74-D4-35-E9-45-71" == benchmark(getmac.GetmacExe().get, arg="Ethernet 2")


def test_windows_10_iface_ipconfig(benchmark, mocker, get_sample):
    content = get_sample("windows_10/ipconfig-all.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert "74-D4-35-E9-45-71" == benchmark(getmac.IpconfigExe().get, arg="Ethernet 3")


def test_windows_10_iface_wmic(benchmark, mocker, get_sample):
    content = get_sample("windows_10/wmic_nic.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert "00:FF:17:15:F8:C8" == benchmark(getmac.WmicExe().get, arg="Ethernet 3")


@pytest.mark.parametrize(
    ("mac", "ip", "sample_file"),
    [("78-28-ca-c4-66-fe", "10.0.0.175", "windows_10/arp_-a_10.0.0.175.out")],
)
def test_arpexe_samples(benchmark, mocker, get_sample, mac, ip, sample_file):
    content = get_sample(sample_file)
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert mac == benchmark(getmac.ArpExe().get, arg=ip)

    mocker.patch("getmac.getmac.check_command", return_value=True)
    assert getmac.ArpExe().test() is True
    getmac.check_command.assert_called_once_with("arp.exe")


def test_openbsd_get_default_iface(benchmark, mocker, get_sample):
    content = get_sample("openbsd_6/route_nq_show_inet_gateway_priority_1.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert "em0" == benchmark(getmac.DefaultIfaceOpenBsd().get)

    mocker.patch("getmac.getmac._popen", return_value="")
    assert not getmac.DefaultIfaceOpenBsd().get()

    mocker.patch("getmac.getmac.check_command", return_value=True)
    assert getmac.DefaultIfaceOpenBsd().test() is True
    getmac.check_command.assert_called_once_with("route")


def test_openbsd_remote(benchmark, mocker, get_sample):
    content = get_sample("openbsd_6/arp_an.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert "52:54:00:12:35:02" == benchmark(getmac.ArpOpenbsd().get, arg="10.0.2.2")
    assert "52:54:00:12:35:03" == getmac.ArpOpenbsd().get("10.0.2.3")
    assert "08:00:27:18:64:56" == getmac.ArpOpenbsd().get("10.0.2.15")

    mocker.patch("getmac.getmac.check_command", return_value=True)
    assert getmac.ArpOpenbsd().test() is True
    getmac.check_command.assert_called_once_with("arp")


def test_freebsd_get_default_iface(benchmark, mocker, get_sample):
    content = get_sample("freebsd11/netstat_r.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert "em0" == benchmark(getmac.DefaultIfaceFreeBsd().get)

    mocker.patch("getmac.getmac.check_command", return_value=True)
    assert getmac.DefaultIfaceFreeBsd().test() is True
    getmac.check_command.assert_called_once_with("netstat")


@pytest.mark.parametrize(
    ("mac", "ip", "sample_file"),
    [
        ("52:54:00:12:35:02", "10.0.2.2", "freebsd11/arp_-a.out"),
        ("08:00:27:ab:b0:67", "10.0.2.15", "freebsd11/arp_-a.out"),
        ("52:54:00:12:35:02", "10.0.2.2", "freebsd11/arp_10-0-2-2.out"),
    ],
)
def test_arpfreebsd_samples(benchmark, mocker, get_sample, mac, ip, sample_file):
    content = get_sample(sample_file)
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert mac == benchmark(getmac.ArpFreebsd().get, arg=ip)

    assert not getmac.ArpFreebsd().get("")
    assert not getmac.ArpFreebsd().get("10.")
    assert not getmac.ArpFreebsd().get("10.10.10.10")
    assert not getmac.ArpFreebsd().get(mac)
    assert not getmac.ArpFreebsd().get("em0")

    mocker.patch("getmac.getmac.check_command", return_value=True)
    assert getmac.ArpFreebsd().test() is True
    getmac.check_command.assert_called_once_with("arp")


@pytest.mark.parametrize(
    ("mac", "ip", "sample_file"),
    [
        ("00:50:56:f1:4c:50", "192.168.16.2", "ubuntu_18.04/cat_proc-net-arp.out"),
        ("00:50:56:e1:a8:4a", "192.168.16.2", "ubuntu_18.10/proc_net_arp.out"),
        ("00:50:56:e8:32:3c", "192.168.16.254", "ubuntu_18.10/proc_net_arp.out"),
        ("00:50:56:c0:00:0a", "192.168.95.1", "ubuntu_18.10/proc_net_arp.out"),
        ("00:50:56:fa:b7:54", "192.168.95.254", "ubuntu_18.10/proc_net_arp.out"),
        ("52:55:0a:00:02:02", "10.0.2.2", "android_6/cat_proc-net-arp.out"),
        ("02:00:00:00:01:00", "192.168.232.1", "android_9/cat_proc-net-arp.out"),
        ("8e:8f:aa:c9:d2:8b", "192.168.200.1", "android_9/cat_proc-net-arp.out"),
    ],
)
def test_arpfile_samples(benchmark, mocker, get_sample, mac, ip, sample_file):
    content = get_sample(sample_file)
    mocker.patch("getmac.getmac._read_file", return_value=content)
    assert mac == benchmark(getmac.ArpFile().get, arg=ip)

    assert not getmac.ArpFile().get("0.0.0.0")
    assert not getmac.ArpFile().get("104.0.0.0")
    assert not getmac.ArpFile().get("")
    assert not getmac.ArpFile().get(mac)

    mocker.patch("getmac.getmac._read_file", return_value=None)
    assert not getmac.ArpFile().get(ip)

    mocker.patch("getmac.getmac._read_file", return_value="")
    assert not getmac.ArpFile().get(ip)


@pytest.mark.parametrize(
    ("mac", "ip", "sample_file"),
    [
        (
            "00:50:56:f1:4c:50",
            "192.168.16.2",
            "ubuntu_18.04/ip_neighbor_show_192-168-16-2.out",
        ),
        ("00:50:56:f1:4c:50", "192.168.16.2", "ubuntu_18.04/ip_neighbor_show.out"),
        ("52:55:0a:00:02:02", "10.0.2.2", "android_6/ip_neighbor_show_10.0.2.2.out"),
        ("52:55:0a:00:02:02", "10.0.2.2", "android_6/ip_neighbor.out"),
        ("52:56:00:00:00:02", "fe80::2", "android_6/ip_neighbor.out"),
        ("8e:8f:aa:c9:d2:8b", "192.168.200.1", "android_9/ip_neighbor.out"),
        ("8e:8f:aa:c9:d2:8b", "fe80::8c8f:aaff:fec9:d28b", "android_9/ip_neighbor.out"),
    ],
)
def test_ipneighshow_samples(benchmark, mocker, get_sample, mac, ip, sample_file):
    content = get_sample(sample_file)
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert mac == benchmark(getmac.IpNeighborShow().get, arg=ip)

    assert getmac.IpNeighborShow().get("bad") is None


@pytest.mark.parametrize(
    ("mac", "iface", "sample_file"),
    [
        ("00:0c:29:b5:72:37", "ens33", "ubuntu_18.04/netstat_iae.out"),
        ("02:42:33:bf:3e:40", "docker0", "ubuntu_18.04/netstat_iae.out"),
        ("08:00:27:e8:81:6f", "eth0", "ubuntu_12.04/netstat_iae.out"),
        ("b4:2e:99:35:1e:84", "eth0", "WSL_ubuntu_18.04/netstat_-iae.out"),
        ("0a:00:27:00:00:0c", "eth4", "WSL_ubuntu_18.04/netstat_-iae.out"),
    ],
)
def test_netstatiface_samples(benchmark, mocker, get_sample, mac, iface, sample_file):
    content = get_sample(sample_file)
    mocker.patch("getmac.getmac._popen", return_value=content)

    assert mac == benchmark(getmac.NetstatIface().get, arg=iface)
    assert getmac.NetstatIface().get("lo") is None
    assert getmac.NetstatIface().get("ens") is None
    assert getmac.NetstatIface().get("ens3") is None
    assert getmac.NetstatIface().get("ens333") is None
    assert getmac.NetstatIface().get("docker") is None
    assert getmac.NetstatIface().get("eth") is None
    assert getmac.NetstatIface().get("eth00") is None
    # TODO: improve netstat regex.
    #   On Linux, it uses the same source as ifconfig (the Kernel Interface Table),
    #   so we can just use the same regex that we use for Ifconfig* methods
    # assert getmac.NetstatIface().get("Kernel") is None
    # assert getmac.NetstatIface().get("e") is None

    mocker.patch("getmac.getmac._popen", return_value=None)
    assert getmac.NetstatIface().get("eth0") is None
    mocker.patch("getmac.getmac._popen", return_value=" ")
    assert getmac.NetstatIface().get("eth0") is None


def test_ip_link_iface_bad_returncode(mocker, get_sample):
    """Test the exception handling works for old-style ip link."""
    content = get_sample("ip_link_list.out")
    cpe = CalledProcessError(cmd="", returncode=255)
    mocker.patch("getmac.getmac._popen", side_effect=[cpe, content])
    except_method = getmac.IpLinkIface()
    assert "74:d4:35:e9:45:71" == except_method.get("eth0")


@pytest.mark.parametrize(
    ("expected_mac", "iface_arg"),
    [
        ("b4:2e:99:36:1e:33", "eth0"),
        ("b4:2e:99:35:1e:86", "eth3"),
        ("00:15:5d:83:d9:0a", "eth8"),
        (None, "lo"),
        ("00:ff:36:20:68:56", "eth15"),
        (None, "eth16"),
        (None, "eth"),
    ],
)
def test_ip_link_iface_wsl(benchmark, mocker, get_sample, expected_mac, iface_arg):
    mocker.patch("getmac.getmac.IpLinkIface._tested_arg", True)
    mocker.patch("getmac.getmac.IpLinkIface._iface_arg", False)
    content = get_sample("WSL_ubuntu_18.04/ip_link.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert expected_mac == benchmark(getmac.IpLinkIface().get, arg=iface_arg)


@pytest.mark.parametrize(
    ("mac", "iface", "sample_file"),
    [
        ("08:00:27:12:33:44", "eth0", "ubuntu_18.04/ip_link_show_eth0.out"),
        ("00:0c:29:b5:72:37", "ens33", "ubuntu_18.04/ip_link_list.out"),
        ("00:0c:29:b5:72:37", "ens33", "ubuntu_18.04/ip_link.out"),
        ("74:d4:35:e9:45:71", "eth0", "ip_link_list.out"),
        ("52:54:00:12:34:56", "eth0", "android_6/ip_link.out"),
        ("46:37:e2:ae:b8:7f", "radio0@if10", "android_9/ip_link.out"),
    ],
)
def test_iplinkiface_samples(benchmark, mocker, get_sample, mac, iface, sample_file):
    content = get_sample(sample_file)
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert mac == benchmark(getmac.IpLinkIface().get, arg=iface)

    # TODO: IpLinkIface regexes need improvements
    # assert getmac.IpLinkIface().get("eth") is None
    # assert getmac.IpLinkIface().get("et") is None
    # assert getmac.IpLinkIface().get("e") is None
    assert getmac.IpLinkIface().get("e0") is None
    assert getmac.IpLinkIface().get("en33") is None
    assert getmac.IpLinkIface().get("sit0") is None
    assert getmac.IpLinkIface().get("radio@if10") is None
    # assert getmac.IpLinkIface().get("") is None


@pytest.mark.parametrize(
    ("expected_iface", "sample_file"),
    [
        ("ens33", "ubuntu_18.04/route_-n.out"),
        ("eth0", "WSL_ubuntu_18.04/route_-n.out"),
        ("eth0", "android_6/route_-n.out"),
    ],
)
def test_default_iface_route_command(
    benchmark, mocker, get_sample, expected_iface, sample_file
):
    content = get_sample(sample_file)
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert expected_iface == benchmark(getmac.DefaultIfaceRouteCommand().get)

    mocker.patch("getmac.getmac._popen", return_value="")
    assert not getmac.DefaultIfaceRouteCommand().get()

    mocker.patch("getmac.getmac._popen", return_value="0.0.0.0 ")
    assert not getmac.DefaultIfaceRouteCommand().get()


@pytest.mark.parametrize(
    ("iface", "sample_file"),
    [
        ("ens33", "ubuntu_18.10/proc_net_route.out"),
        ("eth0", "android_6/cat_proc-net-route.out"),
        (None, "android_9/cat_proc-net-route.out"),
    ],
)
def test_defaultifacelinuxroutefile_samples(
    benchmark, mocker, get_sample, iface, sample_file
):
    content = get_sample(sample_file)
    mocker.patch("getmac.getmac._read_file", return_value=content)
    assert benchmark(getmac.DefaultIfaceLinuxRouteFile().get) == iface


def test_defaultifacelinuxroutefile(mocker):
    mocker.patch("getmac.getmac._read_file", return_value=None)
    assert getmac.DefaultIfaceLinuxRouteFile().get() is None

    mocker.patch("getmac.getmac._read_file", return_value="")
    assert getmac.DefaultIfaceLinuxRouteFile().get() is None


@pytest.mark.parametrize(
    ("iface", "sample_file"),
    [
        ("ens33", "ubuntu_18.04/ip_route_list_0slash0.out"),
        ("eth0", "WSL_ubuntu_18.04/ip_route_list_0slash0.out"),
        ("eth0", "android_6/ip_route_list_0slash0.out"),
    ],
)
def test_defaultifaceiproute_samples(benchmark, mocker, get_sample, iface, sample_file):
    content = get_sample(sample_file)
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert iface == benchmark(getmac.DefaultIfaceIpRoute().get)


def test_defaultifaceiproute(mocker):
    mocker.patch("getmac.getmac._popen", return_value=None)
    assert getmac.DefaultIfaceIpRoute().get() is None

    mocker.patch("getmac.getmac._popen", return_value="")
    assert getmac.DefaultIfaceIpRoute().get() is None

    mocker.patch("getmac.getmac._popen", return_value="asdfalksj3")
    assert not getmac.DefaultIfaceIpRoute().get()


@pytest.mark.parametrize(
    ("iface", "sample_file"),
    [
        ("en0", "macos_10.12.6/route_-n_get_default.out"),
        ("em0", "freebsd11/route_get_default.out"),
    ],
)
def test_defaultifaceroutegetcommand_samples(
    benchmark, mocker, get_sample, iface, sample_file
):
    content = get_sample(sample_file)
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert iface == benchmark(getmac.DefaultIfaceRouteGetCommand().get)

    mocker.patch("getmac.getmac._popen", return_value=None)
    assert not getmac.DefaultIfaceRouteGetCommand().get()

    mocker.patch("getmac.getmac._popen", return_value="")
    assert not getmac.DefaultIfaceRouteGetCommand().get()

    # test with bad input (hit the except indexerror case)
    mocker.patch("getmac.getmac._popen", return_value="interface:")
    assert not getmac.DefaultIfaceRouteGetCommand().get()

    mocker.patch("getmac.getmac.check_command", return_value=True)
    assert getmac.DefaultIfaceRouteGetCommand().test() is True
    getmac.check_command.assert_called_once_with("route")


@pytest.mark.parametrize(
    ("mac", "ip", "sample_file"),
    [
        ("58:6d:8f:07:c9:94", "192.168.1.1", "OSX/arp_-a.out"),
        ("58:6d:8f:07:c9:94", "192.168.1.1", "OSX/arp_-an.out"),
        ("00:50:56:f1:4c:50", "192.168.16.2", "ubuntu_18.04/arp_-a.out"),
        ("00:50:56:f1:4c:50", "192.168.16.2", "ubuntu_18.04/arp_-an.out"),
        ("52:54:00:12:35:02", "10.0.2.2", "freebsd11/arp_10-0-2-2.out"),
        ("52:54:00:12:35:02", "10.0.2.2", "solaris10/arp_10-0-2-2.out"),
    ],
)
def test_arp_various_args(benchmark, mocker, get_sample, mac, ip, sample_file):
    content = get_sample(sample_file)
    mocker.patch("getmac.getmac._popen", return_value=content)
    if "OSX" in sample_file:
        mocker.patch("getmac.getmac.DARWIN", return_value=True)
    elif "solaris" in sample_file:
        mocker.patch("getmac.getmac.SOLARIS", return_value=True)
    result = benchmark(getmac.ArpVariousArgs().get, arg=ip)

    # NOTE: Darwin  and Solaris will return MACs without leading zeroes,
    # e.g. "58:6d:8f:7:c9:94" instead of "58:6d:8f:07:c9:94"
    #
    # It makes more sense to me to just handle the weird mac here
    # in the test instead of adding redundant logic for cleaning
    # the result to the method.
    if "OSX" in sample_file:
        assert result == "58:6d:8f:7:c9:94"
    elif "solaris" in sample_file:
        assert result == "52:54:0:12:35:2"
    if "OSX" in sample_file or "solaris" in sample_file:
        result = getmac._clean_mac(result)

    assert mac == result


def test_sys_iface_file(mocker):
    mocker.patch("getmac.getmac._read_file", return_value="00:0c:29:b5:72:37\n")
    assert getmac.SysIfaceFile().get("ens33") == "00:0c:29:b5:72:37\n"

    mocker.patch("getmac.getmac._read_file", return_value=None)
    assert getmac.SysIfaceFile().get("ens33") is None


@pytest.mark.skipif(
    platform.system() != "Linux",
    reason="Can't reliably mock fcntl on non-Linux platforms",
)
def test_fcntl_iface(mocker):
    data = (
        b"enp3s0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00t\xd45\xe9"
        b"Es\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    )
    mocker.patch("fcntl.ioctl", return_value=data)
    m = mocker.patch("socket.socket")
    assert getmac.FcntlIface().get("enp3s0") == "74:d4:35:e9:45:73"
    m.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)


# Python 2.7.5 (CentOS 7) doesn't have this...
# The commit adding it: https://bit.ly/2Hnd7bN (no idea what release it was in)
@pytest.mark.skipif(
    not hasattr(uuid, "_arp_getnode"),
    reason="This version of Python doesn't have uuid._arp_getnode",
)
def test_uuid_arp_get_node(mocker):
    mocker.patch("uuid._arp_getnode", return_value=278094213753144)
    assert getmac.UuidArpGetNode().get("10.0.0.1") == "FC:EC:DA:D3:29:38"
    mocker.patch("uuid._arp_getnode", return_value=None)
    assert getmac.UuidArpGetNode().get("10.0.0.1") is None
    assert getmac.UuidArpGetNode().get("en0") is None


@pytest.mark.skipif(
    sys.version_info[0] == 3 and sys.version_info[1] >= 9,
    reason="Python 3.9+ doesn't have uuid._find_mac",
)
def test_uuid_lanscan(mocker):
    mocker.patch("uuid._find_mac", return_value=2482700837424)
    assert getmac.UuidLanscan().get("en1") == "02:42:0C:80:62:30"
    mocker.patch("uuid._find_mac", return_value=None)
    assert getmac.UuidLanscan().get("10.0.0.1") is None
    assert getmac.UuidLanscan().get("en0") is None

    mocker.patch("getmac.getmac.check_command", return_value=True)
    assert getmac.UuidLanscan().test() is True
    getmac.check_command.assert_called_once_with("lanscan")
