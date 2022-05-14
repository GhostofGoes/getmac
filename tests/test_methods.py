# -*- coding: utf-8 -*-

from subprocess import CalledProcessError

import pytest

from getmac import getmac


# TODO (rewrite): freebsd11/route_get_default.out


def test_ifconfigether_darwin(benchmark, mocker, get_sample):
    content = get_sample("OSX/ifconfig.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert "2c:f0:ee:2f:c7:de" == benchmark(getmac.IfconfigEther().get, arg="en0")
    assert "b2:eb:94:59:0b:d4" == getmac.IfconfigEther().get("awdl0")
    assert "32:00:10:bf:60:00" == getmac.IfconfigEther().get("bridge0")
    assert not getmac.IfconfigEther().get("lo0")
    assert not getmac.IfconfigEther().get("XHC20")
    assert not getmac.IfconfigEther().get("utun0")


# TODO (rewrite): several of these should be a different method without a interface arg
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


def test_ubuntu_1204_netstat(benchmark, mocker, get_sample):
    # TODO (rewrite): freebsd11/netstat_-ia.out
    content = get_sample("ubuntu_12.04/netstat_iae.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    mocker.patch("getmac.getmac.DEBUG", 4)

    assert "08:00:27:e8:81:6f" == benchmark(getmac.NetstatIface().get, arg="eth0")
    assert getmac.NetstatIface().get("lo") is None
    assert getmac.NetstatIface().get("ens") is None
    assert getmac.NetstatIface().get("eth") is None
    assert getmac.NetstatIface().get("eth00") is None


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


def test_ubuntu_1804_ip_route_default_iface(benchmark, mocker, get_sample):
    content = get_sample("ubuntu_18.04/ip_route_list_0slash0.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert "ens33" == benchmark(getmac.DefaultIfaceIpRoute().get)


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


def test_freebsd_get_default_iface(benchmark, mocker, get_sample):
    content = get_sample("freebsd11/netstat_r.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert "em0" == benchmark(getmac.DefaultIfaceFreeBsd().get)


def test_freebsd_remote(benchmark, mocker, get_sample):
    # TODO (rewrite): freebsd11/arp_-a.out
    content = get_sample("freebsd11/arp_10-0-2-2.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert "52:54:00:12:35:02" == benchmark(getmac.ArpFreebsd().get, arg="10.0.2.2")


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


def test_wsl_ip_route_default_iface(benchmark, mocker, get_sample):
    content = get_sample("WSL_ubuntu_18.04/ip_route_list_0slash0.out")
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert "eth0" == benchmark(getmac.DefaultIfaceIpRoute().get)


@pytest.mark.parametrize(
    ("expected_iface", "sample_file"),
    [
        ("ens33", "ubuntu_18.04/route_-n.out"),
        ("eth0", "WSL_ubuntu_18.04/route_-n.out"),
    ],
)
def test_default_iface_route_command(
    benchmark, mocker, get_sample, expected_iface, sample_file
):
    content = get_sample(sample_file)
    mocker.patch("getmac.getmac._popen", return_value=content)
    assert expected_iface == benchmark(getmac.DefaultIfaceRouteCommand().get)


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
