# -*- coding: utf-8 -*-

from subprocess import CalledProcessError

import pytest

from getmac import getmac


def test_ifconfig_linux(benchmark, mocker, get_sample):
    content = get_sample("ifconfig.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert "74:d4:35:e9:45:71" == benchmark(getmac.IfconfigLinux().get, arg="eth0")


def test_ip_link_iface_old_style(benchmark, mocker, get_sample):
    content = get_sample("ip_link_list.out")
    # Test the exception handling works for old-style ip link
    cpe = CalledProcessError(cmd="", returncode=255)
    mocker.patch("getmac.getmac._popen", side_effect=[cpe, content])
    except_method = getmac.IpLinkIface()
    assert "74:d4:35:e9:45:71" == except_method.get("eth0")
    # benchmark performance
    mocker.patch("getmac.getmac._popen", return_value=content)
    bench_method = getmac.IpLinkIface()
    assert "74:d4:35:e9:45:71" == benchmark(bench_method.get, arg="eth0")


def test_default_iface_linux_route_file(benchmark, mocker, get_sample):
    content = get_sample("ubuntu_18.10/proc_net_route.out")
    mocker.patch("getmac.getmac._read_file", return_value=content)
    assert benchmark(getmac.DefaultIfaceLinuxRouteFile().get) == "ens33"


def test_arping_host_habets(benchmark, mocker, get_sample):
    content = get_sample("ubuntu_18.04/arping-habets.out")
    cpe = CalledProcessError(cmd="", returncode=1)
    mocker.patch("getmac.getmac._popen", side_effect=cpe)
    ap = getmac.ArpingHost()
    ap.get("192.168.16.254")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert "00:50:56:e8:32:3c" == benchmark(ap.get, arg="192.168.16.254")


def test_arping_host_iputils(benchmark, mocker, get_sample):
    content = get_sample("ubuntu_18.04/arping-iputils.out")
    cpe = CalledProcessError(cmd="", returncode=2)
    mocker.patch("getmac.getmac._popen", side_effect=cpe)
    ap = getmac.ArpingHost()
    ap.get("192.168.16.254")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert "00:50:56:E8:32:3C" == benchmark(ap.get, arg="192.168.16.254")


def test_ubuntu_1804_interface(mocker, get_sample):
    content = get_sample("ubuntu_18.04/ifconfig_ens33.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert "00:0c:29:b5:72:37" == getmac.IfconfigLinux().get("ens33")

    content = get_sample("ubuntu_18.04/ip_link_list.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert "00:0c:29:b5:72:37" == getmac.IpLinkIface().get("ens33")

    content = get_sample("ubuntu_18.04/ip_link.out")
    cpe = CalledProcessError(cmd="", returncode=255)
    mocker.patch("getmac.getmac._popen", side_effect=[cpe, content])
    assert "00:0c:29:b5:72:37" == getmac.IpLinkIface().get("ens33")


def test_ubuntu_1804_netstat(benchmark, mocker, get_sample):
    content = get_sample("ubuntu_18.04/netstat_iae.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert "00:0c:29:b5:72:37" == benchmark(getmac.NetstatIface().get, arg="ens33")
    assert "02:42:33:bf:3e:40" == getmac.NetstatIface().get("docker0")
    assert getmac.NetstatIface().get("lo") is None
    assert getmac.NetstatIface().get("ens") is None
    assert getmac.NetstatIface().get("ens3") is None
    assert getmac.NetstatIface().get("ens333") is None
    assert getmac.NetstatIface().get("docker") is None


def test_ubuntu_1804_remote(benchmark, mocker, get_sample):
    content = get_sample("ubuntu_18.04/arp_-a.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert "00:50:56:f1:4c:50" == benchmark(
        getmac.ArpVariousArgs().get, arg="192.168.16.2"
    )
    content = get_sample("ubuntu_18.04/arp_-an.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert "00:50:56:f1:4c:50" == getmac.ArpVariousArgs().get("192.168.16.2")


def test_ubuntu_1804_arp_file(mocker, get_sample):
    content = get_sample("ubuntu_18.04/cat_proc-net-arp.out")
    mocker.patch("getmac.getmac._read_file", return_value=content)
    assert "00:50:56:f1:4c:50" == getmac.ArpFile().get("192.168.16.2")
    mocker.patch("getmac.getmac._read_file", return_value=None)
    assert not getmac.ArpFile().get("192.168.16.2")


def test_ubuntu_1804_ip_neigh_show_with_arg(benchmark, mocker, get_sample):
    content = get_sample("ubuntu_18.04/ip_neighbor_show_192-168-16-2.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert "00:50:56:f1:4c:50" == benchmark(
        getmac.IpNeighShow().get, arg="192.168.16.2"
    )


def test_ubuntu_1804_ip_neigh_show_no_arg(benchmark, mocker, get_sample):
    content = get_sample("ubuntu_18.04/ip_neighbor_show.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert "00:50:56:f1:4c:50" == benchmark(
        getmac.IpNeighShow().get, arg="192.168.16.2"
    )


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


def test_darwin_interface(benchmark, mocker, get_sample):
    content = get_sample("OSX/ifconfig.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    # TODO: is the ".*" in _arg_regex necessary?
    ether = getmac.IfconfigEther()
    ether._tested_arg = True
    ether._iface_arg = False
    assert "2c:f0:ee:2f:c7:de" == benchmark(ether.get, arg="en0")


def test_darwin_remote(benchmark, mocker, get_sample):
    content = get_sample("OSX/arp_-a.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert "58:6d:8f:07:c9:94" == getmac._clean_mac(
        getmac.ArpVariousArgs().get("192.168.1.1")
    )
    assert "58:6d:8f:7:c9:94" == benchmark(
        getmac.ArpVariousArgs().get, arg="192.168.1.1"
    )
    content = get_sample("OSX/arp_-an.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert "58:6d:8f:07:c9:94" == getmac._clean_mac(
        getmac.ArpVariousArgs().get("192.168.1.1")
    )
    assert "58:6d:8f:7:c9:94" == getmac.ArpVariousArgs().get("192.168.1.1")


def test_openbsd_interface(benchmark, mocker, get_sample):
    content = get_sample("openbsd_6/ifconfig.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert "08:00:27:18:64:56" == getmac.IfconfigOpenbsd().get("em0")

    content = get_sample("openbsd_6/ifconfig_em0.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert "08:00:27:18:64:56" == benchmark(getmac.IfconfigOpenbsd().get, arg="em0")


def test_openbsd_get_default_iface(benchmark, mocker, get_sample):
    content = get_sample("openbsd_6/route_nq_show_inet_gateway_priority_1.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert "em0" == benchmark(getmac.DefaultIfaceOpenBsd().get)


def test_openbsd_remote(benchmark, mocker, get_sample):
    content = get_sample("openbsd_6/arp_an.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert "52:54:00:12:35:02" == benchmark(getmac.ArpOpenbsd().get, arg="10.0.2.2")
    assert "52:54:00:12:35:03" == getmac.ArpOpenbsd().get("10.0.2.3")
    assert "08:00:27:18:64:56" == getmac.ArpOpenbsd().get("10.0.2.15")


def test_freebsd_interface(benchmark, mocker, get_sample):
    content = get_sample("freebsd11/ifconfig_em0.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    # TODO: shouldn't this test pass if _iface_arg = True? need another sample
    ether = getmac.IfconfigEther()
    ether._tested_arg = True
    ether._iface_arg = False
    assert "08:00:27:33:37:26" == benchmark(ether.get, arg="em0")


def test_freebsd_get_default_iface(benchmark, mocker, get_sample):
    content = get_sample("freebsd11/netstat_r.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert "em0" == benchmark(getmac.DefaultIfaceFreeBsd().get)


def test_freebsd_remote(benchmark, mocker, get_sample):
    content = get_sample("freebsd11/arp_10-0-2-2.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert "52:54:00:12:35:02" == benchmark(getmac.ArpFreebsd().get, arg="10.0.2.2")


def test_wsl_ifconfig(benchmark, mocker, get_sample):
    content = get_sample("WSL_ubuntu_18.04/ifconfig_eth8.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert "00:15:5d:83:d9:0a" == benchmark(getmac.IfconfigLinux().get, arg="eth8")


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
def test_wsl_ip_link_iface(benchmark, mocker, get_sample, expected_mac, iface_arg):
    mocker.patch("getmac.getmac.IpLinkIface._tested_arg", True)
    mocker.patch("getmac.getmac.IpLinkIface._iface_arg", False)
    content = get_sample("WSL_ubuntu_18.04/ip_link.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert expected_mac == benchmark(getmac.IpLinkIface().get, arg=iface_arg)
