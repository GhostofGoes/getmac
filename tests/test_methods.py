import ctypes
import errno
import platform
import socket
import sys
from subprocess import CalledProcessError

import pytest

from getmac import getmac, utils
from getmac.variables import consts

# TODO: freebsd11/netstat_-ia.out
# TODO: netstat_-ian_aix.out
# TODO: netstat_-ian_unknown.out
# TODO: macos_10.12.6/netstat_-i.out
# TODO: macos_10.12.6/netstat_-ia.out


@pytest.mark.parametrize(
    ("mac", "iface", "sample_file"),
    [
        ("08:00:27:2b:c2:ed", "en0", "macos_10.12.6/networksetup_-getmacaddress_en0.out"),
        ("02:00:00:00:00:10", "en0", "macos_26.6.2/networksetup_-getmacaddress_en0.out"),
        ("02:00:00:00:00:11", "en1", "macos_26.6.2/networksetup_-getmacaddress_en1.out"),
    ],
)
def test_darwinnetworksetupiface_samples(benchmark, mocker, get_sample, mac, iface, sample_file):
    mocker.patch("getmac.utils.popen", return_value=get_sample(sample_file))
    assert mac == benchmark(getmac.DarwinNetworksetupIface().get, arg=iface)
    utils.popen.assert_called_with("networksetup", f"-getmacaddress {iface}")


def test_darwinnetworksetupiface(mocker):

    mocker.patch("getmac.utils.popen", return_value=None)
    assert not getmac.DarwinNetworksetupIface().get("en0")
    mocker.patch("getmac.utils.popen", return_value="")
    assert not getmac.DarwinNetworksetupIface().get("en0")

    mocker.patch("getmac.utils.check_command", return_value=False)
    assert getmac.DarwinNetworksetupIface().test() is False
    utils.check_command.assert_called_once_with("networksetup")


def test_darwinnetworksetupiface_not_a_hardware_port(mocker, get_sample):
    """
    networksetup exits with code 4 for interfaces that aren't hardware ports, like VPN
    tunnels (GitHub issue #91). That's "no MAC", so it isn't raised (marking it unusable).
    The sample is from macOS 26.6.2, where it printed this to stdout and exited with 4.
    """
    output = get_sample("macos_26.6.2/networksetup_-getmacaddress_utun0.out")
    assert output == "** Error: The parameters were not valid.\n"
    cpe = CalledProcessError(
        cmd="networksetup -getmacaddress utun0", returncode=4, output=output.encode()
    )
    mocker.patch("getmac.utils.popen", side_effect=cpe)
    assert getmac.DarwinNetworksetupIface().get("utun0") is None

    # Other errors are still raised
    cpe = CalledProcessError(cmd="networksetup -getmacaddress en0", returncode=2)
    mocker.patch("getmac.utils.popen", side_effect=cpe)
    with pytest.raises(CalledProcessError):
        getmac.DarwinNetworksetupIface().get("en0")


FACTER_IFCONFIG = "third_party/facter/ifconfig/"
GLPI_IFCONFIG = "third_party/glpi_agent/generic/ifconfig/"

ifconfigether_samples = [
    ("2c:f0:ee:2f:c7:de", "en0", "OSX/ifconfig.out"),
    ("08:00:27:2b:c2:ed", "en0", "macos_10.12.6/ifconfig.out"),
    ("08:00:27:2b:c2:ed", "en0", "macos_10.12.6/ifconfig_en0.out"),
    # Mac OS X 10.5 - 10.6 (Facter samples)
    ("00:1b:63:ae:02:66", "en0", FACTER_IFCONFIG + "Mac_OS_X_10.5.5_ifconfig"),
    ("00:1e:52:70:d7:b6", "en1", FACTER_IFCONFIG + "Mac_OS_X_10.5.5_ifconfig"),
    ("00:17:f2:06:e4:2e", "en0", FACTER_IFCONFIG + "darwin_9_8_0"),
    ("00:50:56:c0:00:01", "vmnet1", FACTER_IFCONFIG + "darwin_9_8_0"),
    ("00:17:f2:06:e4:2e", "en0", FACTER_IFCONFIG + "darwin_9_8_0_en0"),
    ("00:17:f2:06:e3:c2", "en0", FACTER_IFCONFIG + "darwin_10_3_0"),
    ("00:17:f2:06:e3:c3", "en1", FACTER_IFCONFIG + "darwin_10_3_0"),
    ("00:50:56:c0:00:08", "vmnet8", FACTER_IFCONFIG + "darwin_10_3_0"),
    ("00:17:f2:06:e3:c2", "en0", FACTER_IFCONFIG + "darwin_10_3_0_en0"),
    ("58:b0:35:fa:08:b1", "en0", FACTER_IFCONFIG + "darwin_10_6_4"),
    ("58:b0:35:7f:25:b3", "en1", FACTER_IFCONFIG + "darwin_10_6_4"),
    ("0a:00:27:00:00:00", "vboxnet0", FACTER_IFCONFIG + "darwin_10_6_4"),
    ("58:b0:35:7f:25:b3", "en1", FACTER_IFCONFIG + "darwin_10_6_4_en1"),
    ("00:25:4b:ca:56:72", "en0", FACTER_IFCONFIG + "darwin_10_6_6_dualstack"),
    ("00:25:00:48:19:ef", "en1", FACTER_IFCONFIG + "darwin_10_6_6_dualstack_en1"),
    ("00:23:32:d5:ee:34", "en0", FACTER_IFCONFIG + "darwin_ifconfig_all_with_multiple_interfaces"),
    ("00:11:33:22:55:44", "en1", FACTER_IFCONFIG + "darwin_ifconfig_all_with_multiple_interfaces"),
    ("00:1c:b3:be:81:c9", "en1", FACTER_IFCONFIG + "darwin_ifconfig_single_interface"),
    # Newer macOS, with VLAN (en0.1), bridge and AWDL interfaces
    ("64:5a:ed:ea:5c:81", "en0", "third_party/facter/ifconfig_mac"),
    ("08:00:27:f5:23:f7", "en0.1", "third_party/facter/ifconfig_mac"),
    ("82:17:0e:93:9d:00", "bridge0", "third_party/facter/ifconfig_mac"),
    ("06:5a:ed:ea:5c:81", "p2p0", "third_party/facter/ifconfig_mac"),
    ("2e:ba:e4:83:4b:b7", "awdl0", "third_party/facter/ifconfig_mac"),
]


@pytest.mark.parametrize(("mac", "iface", "sample_file"), ifconfigether_samples)
def test_ifconfigether_darwin(benchmark, mocker, get_sample, mac, iface, sample_file):
    content = get_sample(sample_file)
    mocker.patch("getmac.utils.popen", return_value=content)
    assert mac == benchmark(getmac.IfconfigEther().get, arg=iface)

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
    # "." isn't a wildcard
    assert not getmac.IfconfigEther().get("en.")


def test_ifconfigether_iface_arg(mocker, get_sample):
    content = get_sample("macos_10.12.6/ifconfig_en0.out")
    mocker.patch("getmac.utils.popen", return_value=content)

    inst = getmac.IfconfigEther()
    assert inst.get("en0") == "08:00:27:2b:c2:ed"
    # "ifconfig en0" is only run once
    utils.popen.assert_called_once_with("ifconfig", "en0")
    assert inst._tested_arg is True
    assert inst._iface_arg is True

    # A missing interface doesn't change that, and "ifconfig" isn't run without it
    cpe = CalledProcessError(cmd="ifconfig en9", returncode=1)
    mocker.patch("getmac.utils.popen", side_effect=cpe)
    assert inst.get("en9") is None
    utils.popen.assert_called_once_with("ifconfig", "en9")
    assert inst._iface_arg is True


def test_ifconfigether_missing_iface_first(mocker, get_sample):
    """If the first lookup is for a missing interface, the argument is tried again later."""
    cpe = CalledProcessError(cmd="ifconfig en9", returncode=1)
    content = get_sample("macos_10.12.6/ifconfig.out")
    mocker.patch("getmac.utils.popen", side_effect=[cpe, content])

    inst = getmac.IfconfigEther()
    assert inst.get("en9") is None
    assert utils.popen.call_args_list == [
        mocker.call("ifconfig", "en9"),
        mocker.call("ifconfig", ""),
    ]
    assert inst._tested_arg is False

    mocker.patch("getmac.utils.popen", return_value=get_sample("macos_10.12.6/ifconfig_en0.out"))
    assert inst.get("en0") == "08:00:27:2b:c2:ed"
    utils.popen.assert_called_once_with("ifconfig", "en0")
    assert inst._iface_arg is True


def test_ifconfigether_no_iface_arg(mocker, get_sample):
    """If "ifconfig <iface>" fails for an interface that exists, "ifconfig" is used."""
    cpe = CalledProcessError(cmd="ifconfig en0", returncode=1)
    content = get_sample("macos_10.12.6/ifconfig.out")
    mocker.patch("getmac.utils.popen", side_effect=[cpe, content])

    inst = getmac.IfconfigEther()
    assert inst.get("en0") == "08:00:27:2b:c2:ed"
    assert inst._tested_arg is True
    assert inst._iface_arg is False

    mocker.patch("getmac.utils.popen", return_value=content)
    assert inst.get("en0") == "08:00:27:2b:c2:ed"
    utils.popen.assert_called_once_with("ifconfig", "")


@pytest.mark.parametrize(
    ("mac", "iface", "sample_file"),
    [
        # Output of "ifconfig" (all interfaces) from older net-tools on Linux,
        # where the MAC is on the same line as the interface name
        ("52:54:00:12:34:56", "eth0", "android_6/ifconfig.out"),
        ("08:00:27:e8:81:6f", "eth0", "ubuntu_12.04/ifconfig.out"),
        ("16:8D:2A:15:17:91", "eth0", FACTER_IFCONFIG + "centos_5_5"),
        ("00:17:F2:06:E4:26", "eth0", FACTER_IFCONFIG + "fedora_10"),
        ("00:50:56:C0:00:01", "vmnet1", FACTER_IFCONFIG + "fedora_10"),
        ("00:50:56:C0:00:08", "vmnet8", FACTER_IFCONFIG + "fedora_10"),
        ("00:17:F2:0D:9B:A8", "eth0", FACTER_IFCONFIG + "fedora_13"),
        ("00:18:F3:F6:33:E5", "eth0:2", FACTER_IFCONFIG + "fedora_8"),
        (
            "00:12:3f:be:22:01",
            "eth0",
            FACTER_IFCONFIG + "linux_ifconfig_all_with_multiple_interfaces",
        ),
        ("00:16:CB:A6:D4:3A", "eth0", FACTER_IFCONFIG + "ubuntu_7_04"),
        # 9 character name, so only one space before "Link encap"
        ("00:17:F2:49:E0:E6", "ath0:avah", FACTER_IFCONFIG + "ubuntu_7_04"),
        ("A4:BA:DB:A5:F5:FA", "eth0", GLPI_IFCONFIG + "dell-xt2"),
        ("4E:8C:81:ED:9B:35", "pan0", GLPI_IFCONFIG + "dell-xt2"),
        ("00:24:D6:6F:81:3A", "wlan0", GLPI_IFCONFIG + "dell-xt2"),
        ("00:50:56:AD:00:0E", "bond0", GLPI_IFCONFIG + "linux-bonding"),
        ("00:1E:68:2F:85:D8", "peth0", GLPI_IFCONFIG + "linux-rhel5.6"),
        ("FE:FF:FF:FF:FF:FF", "vif1.0", GLPI_IFCONFIG + "linux-rhel5.6"),
    ],
)
def test_ifconfigother_samples(benchmark, mocker, get_sample, mac, iface, sample_file):
    mocker.patch("getmac.utils.popen", return_value=get_sample(sample_file))
    assert mac == benchmark(getmac.IfconfigOther().get, arg=iface)
    utils.popen.assert_called_with("ifconfig", "")

    assert getmac.IfconfigOther().get("lo") is None
    assert getmac.IfconfigOther().get("sit0") is None


def test_ifconfigother_edge_cases(mocker):
    # Test the test function
    mocker.patch("getmac.utils.check_command", return_value=False)
    assert getmac.IfconfigOther().test() is False
    utils.check_command.assert_called_once_with("ifconfig")

    assert getmac.IfconfigOther().get("") is None


def test_ifconfigother_fallback_args(mocker, get_sample):
    # "ifconfig" without arguments fails, so "ifconfig -a" is used instead
    content = get_sample(FACTER_IFCONFIG + "centos_5_5")
    cpe = CalledProcessError(cmd="ifconfig", returncode=1)
    mocker.patch("getmac.utils.popen", side_effect=[cpe, content, content])

    inst = getmac.IfconfigOther()
    assert inst.get("eth0") == "16:8D:2A:15:17:91"
    utils.popen.assert_called_with("ifconfig", "-a")

    # The arguments that worked are reused for the next lookup
    assert inst.get("eth0") == "16:8D:2A:15:17:91"
    assert utils.popen.call_count == 3
    utils.popen.assert_called_with("ifconfig", "-a")


@pytest.mark.parametrize("args", ["", "-a"])
def test_ifconfigother_infiniband(mocker, get_sample, args):
    """InfiniBand has a 20 byte "HWaddr", its first 6 bytes aren't a MAC."""
    content = get_sample(FACTER_IFCONFIG + "linux_ifconfig_ib0") + "\n"
    content += get_sample(FACTER_IFCONFIG + "ubuntu_7_04")
    outputs = [content, content]
    if args:  # "ifconfig" without arguments fails, so "ifconfig -a" is used
        outputs.insert(0, CalledProcessError(cmd="ifconfig", returncode=1))
    mocker.patch("getmac.utils.popen", side_effect=outputs)

    inst = getmac.IfconfigOther()
    assert inst.get("ib0") is None
    assert inst.get("eth0") == "00:16:CB:A6:D4:3A"
    utils.popen.assert_called_with("ifconfig", args)


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
    ("52:54:00:12:34:56", "eth0", "android_6/ifconfig_eth0.out"),
    ("00:0c:29:b5:72:37", "ens33", "ubuntu_18.04/ifconfig.out"),
    ("02:42:33:bf:3e:40", "docker0", "ubuntu_18.04/ifconfig.out"),
    ("b4:2e:99:36:1e:64", "eth0", "WSL_ubuntu_18.04/ifconfig.out"),
    ("00:15:5d:83:d9:0a", "eth8", "WSL_ubuntu_18.04/ifconfig.out"),
    # NetBSD uses "address:" instead of "ether"
    ("08:00:27:ce:da:53", "wm0", "netbsd8.2/ifconfig.out"),
    ("08:00:27:ce:da:53", "wm0", "netbsd8.2/ifconfig_wm0.out"),
    # Facter samples
    ("00:0e:0c:68:67:7c", "fxp0", FACTER_IFCONFIG + "6.0-STABLE_FreeBSD_ifconfig"),
    ("00:0e:0c:68:67:7c", "fxp0", FACTER_IFCONFIG + "freebsd_6_0"),
    ("00:0b:db:93:09:67", "bge0", FACTER_IFCONFIG + "bsd_ifconfig_all_with_multiple_interfaces"),
    ("00:0b:db:93:09:68", "bge1", FACTER_IFCONFIG + "bsd_ifconfig_all_with_multiple_interfaces"),
    ("16:8D:2A:15:17:91", "eth0", FACTER_IFCONFIG + "centos_5_5"),
    ("16:8D:2A:15:17:91", "eth0", FACTER_IFCONFIG + "centos_5_5_eth0"),
    ("00:17:F2:06:E4:26", "eth0", FACTER_IFCONFIG + "fedora_10_eth0"),
    ("00:17:F2:0D:9B:A8", "eth0", FACTER_IFCONFIG + "fedora_13"),
    ("00:17:F2:0D:9B:A8", "eth0", FACTER_IFCONFIG + "fedora_13_eth0"),
    ("00:18:F3:F6:33:E5", "eth0", FACTER_IFCONFIG + "fedora_8"),
    ("00:18:F3:F6:33:E5", "eth0:1", FACTER_IFCONFIG + "fedora_8"),  # Alias interface
    ("00:18:F3:F6:33:E5", "eth0", FACTER_IFCONFIG + "fedora_8_eth0"),
    ("00:12:3f:be:22:01", "eth0", FACTER_IFCONFIG + "linux_ifconfig_all_with_multiple_interfaces"),
    ("00:21:cc:4b:29:7d", "em1", FACTER_IFCONFIG + "linux_ifconfig_no_addr"),
    ("00:16:CB:A6:D4:3A", "eth0", FACTER_IFCONFIG + "ubuntu_7_04"),
    ("00:17:F2:49:E0:E6", "ath0", FACTER_IFCONFIG + "ubuntu_7_04"),
    ("00:16:CB:A6:D4:3A", "eth0", FACTER_IFCONFIG + "ubuntu_7_04_eth0"),
    # GLPI Agent samples
    ("08:00:27:2e:70:97", "em0", GLPI_IFCONFIG + "dragonfly-1"),
    ("3c:a9:f4:5a:04:b8", "iwn0", GLPI_IFCONFIG + "freebsd-4"),
    ("3c:a9:f4:5a:04:b8", "wlan0", GLPI_IFCONFIG + "freebsd-4"),
    ("c8:0a:a9:3f:35:fa", "re0", GLPI_IFCONFIG + "freebsd-8.1"),
    ("02:24:1b:9d:ca:01", "fwe0", GLPI_IFCONFIG + "freebsd-8.1"),
    ("0a:00:27:00:00:00", "vboxnet0", GLPI_IFCONFIG + "freebsd-8.1"),
    ("00:16:18:87:ca:b5", "bce0", GLPI_IFCONFIG + "freebsd-bis"),
    ("00:16:18:87:ca:b6", "bce1", GLPI_IFCONFIG + "freebsd-bis"),
    ("00:23:18:cf:0d:93", "em0", GLPI_IFCONFIG + "freebsd-ter"),
    ("4c:ed:de:2c:9d:9a", "wlan0", GLPI_IFCONFIG + "freebsd-ter"),
    ("48:5b:39:c6:53:ba", "eth0", GLPI_IFCONFIG + "linux-archlinux"),
    ("0a:00:27:00:00:00", "vboxnet0", GLPI_IFCONFIG + "linux-archlinux"),
    ("00:50:56:AD:00:0E", "bond0", GLPI_IFCONFIG + "linux-bonding"),
    ("00:50:56:AD:00:0E", "eth0", GLPI_IFCONFIG + "linux-bonding"),
    ("02:42:0c:d5:0f:d7", "docker0", GLPI_IFCONFIG + "linux-el8"),
    ("e4:11:5b:ed:36:0c", "eth0", GLPI_IFCONFIG + "linux-el8"),
    ("e4:11:5b:ed:36:38", "eth1", GLPI_IFCONFIG + "linux-el8"),
    ("e4:11:5b:ed:36:0c", "eth0:srv", GLPI_IFCONFIG + "linux-el8"),
    ("4e:05:62:03:69:e7", "macvlan0", GLPI_IFCONFIG + "linux-el8"),
    ("00:23:ae:8c:33:b6", "em1", GLPI_IFCONFIG + "linux-fc17"),
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
    if "docker0:" not in content:  # Some samples have a real docker0 interface
        assert not getmac._parse_ifconfig("docker0", content)
    assert not getmac._parse_ifconfig("XHC20", content)
    assert not getmac._parse_ifconfig("utun0", content)
    assert not getmac._parse_ifconfig("enc0", content)
    assert not getmac._parse_ifconfig("pflog0", content)
    assert not getmac._parse_ifconfig("", content)


@pytest.mark.parametrize(
    ("iface", "sample_file"),
    [
        # Android 9 emulator, "Link encap:UNSPEC" without a MAC
        ("wlan0", "android_9/ifconfig.out"),
        ("radio0", "android_9/ifconfig.out"),
        ("wlan0", "android_9/ifconfig_wlan0.out"),
        # Solaris only shows the MAC to root (and then with short octets,
        # see test_parse_ifconfig_short_octets)
        ("e1000g0", "solaris10/ifconfig_-a.out"),
        ("e1000g0", "solaris10/ifconfig_e1000g0.out"),
        ("e1000g0", FACTER_IFCONFIG + "solaris_ifconfig_all_with_multiple_interfaces"),
        ("bge0", FACTER_IFCONFIG + "sunos_ifconfig_all_with_multiple_interfaces"),
        ("e1000g0", GLPI_IFCONFIG + "oi-2021.10"),
        ("lo", FACTER_IFCONFIG + "linux_ifconfig_no_mac"),
        # OpenVZ venet and Atheros wifi0 have a 16 byte "HWaddr" with dashes, not a MAC
        ("venet0", FACTER_IFCONFIG + "linux_ifconfig_venet"),
        ("venet0:0", FACTER_IFCONFIG + "linux_ifconfig_venet"),
        ("wifi0", FACTER_IFCONFIG + "ubuntu_7_04"),
        # InfiniBand has a 20 byte "HWaddr", its first 6 bytes aren't a MAC
        ("ib0", FACTER_IFCONFIG + "linux_ifconfig_ib0"),
        ("sit0", GLPI_IFCONFIG + "linux-bonding"),
        # The interface after sit0 (wlan0) has a MAC, it isn't sit0's
        ("sit0", GLPI_IFCONFIG + "dell-xt2"),
        ("faith0", GLPI_IFCONFIG + "dragonfly-1"),
        ("tun0", GLPI_IFCONFIG + "freebsd-8.1"),
        # IP over FireWire, the "lladdr" isn't a MAC
        ("fwip0", GLPI_IFCONFIG + "freebsd-8.1"),
        # FireWire on macOS, the "lladdr" is 8 bytes (EUI-64), not a MAC
        ("fw0", FACTER_IFCONFIG + "darwin_10_3_0"),
    ],
)
def test_parse_ifconfig_no_mac(mocker, get_sample, iface, sample_file):
    content = get_sample(sample_file)
    assert getmac._parse_ifconfig(iface, content) is None

    mocker.patch("getmac.utils.popen", return_value=content)
    assert getmac.IfconfigWithIfaceArg().get(iface) is None


@pytest.mark.parametrize(
    ("iface", "sample_file"),
    [
        ("ib0", FACTER_IFCONFIG + "linux_ifconfig_ib0"),
        ("venet0:1", FACTER_IFCONFIG + "linux_ifconfig_venet"),
        ("lo", FACTER_IFCONFIG + "linux_ifconfig_no_mac"),
    ],
)
def test_parse_ifconfig_no_mac_before_mac(get_sample, iface, sample_file):
    """
    An interface without a MAC that's listed before one with a MAC
    must not get the MAC of the interface after it.
    """
    # Blank line between interfaces, like "ifconfig" from net-tools prints
    content = get_sample(sample_file) + "\n" + get_sample(FACTER_IFCONFIG + "ubuntu_7_04")
    assert getmac._parse_ifconfig(iface, content) is None
    assert getmac._parse_ifconfig("ath0", content) == "00:17:F2:49:E0:E6"


@pytest.mark.parametrize(
    ("mac", "raw_mac", "iface", "sample_file"),
    [
        (
            "00:0c:29:c1:70:2a",
            "0:c:29:c1:70:2a",
            "e1000g0",
            FACTER_IFCONFIG + "solaris_ifconfig_single_interface",
        ),
        ("00:50:56:9a:45:1c", "0:50:56:9a:45:1c", "net0", "third_party/facter/solaris_ifconfig"),
        ("08:00:20:d1:6d:79", "8:0:20:d1:6d:79", "hme0", FACTER_IFCONFIG + "open_solaris_10"),
        ("00:1e:c9:43:55:f9", "0:1e:c9:43:55:f9", "bge0", FACTER_IFCONFIG + "open_solaris_b132"),
        ("02:08:20:89:75:75", "2:8:20:89:75:75", "int0", FACTER_IFCONFIG + "open_solaris_b132"),
        ("00:15:17:7a:60:30", "0:15:17:7a:60:30", "e1000g0", GLPI_IFCONFIG + "solaris-10"),
        ("08:00:27:fc:ad:56", "8:0:27:fc:ad:56", "e1000g0", GLPI_IFCONFIG + "opensolaris"),
        # Debian GNU/kFreeBSD
        (
            "00:11:0a:59:67:90",
            "0:11:a:59:67:90",
            "em0",
            FACTER_IFCONFIG + "debian_kfreebsd_ifconfig",
        ),
    ],
)
def test_parse_ifconfig_short_octets(mocker, get_sample, mac, raw_mac, iface, sample_file):
    """
    Solaris (as root) and kFreeBSD print the MAC without leading zeros
    in each octet, e.g. "ether 0:c:29:c1:70:2a".
    """
    content = get_sample(sample_file)
    assert getmac._parse_ifconfig(iface, content) == raw_mac
    assert utils.clean_mac(raw_mac) == mac

    mocker.patch("getmac.utils.popen", return_value=content)
    assert getmac.IfconfigWithIfaceArg().get(iface) == raw_mac


def test_parse_ifconfig_bad_params():
    assert not getmac._parse_ifconfig(None, None)
    assert not getmac._parse_ifconfig("", "")
    assert not getmac._parse_ifconfig("   ", "")
    assert not getmac._parse_ifconfig("   ", "        ")
    assert not getmac._parse_ifconfig("   ", "     ether   ")


@pytest.mark.parametrize(("mac", "iface", "sample_file"), ifconfig_samples)
def test_ifconfigwithifacearg_samples(mocker, get_sample, mac, iface, sample_file):
    content = get_sample(sample_file)
    mocker.patch("getmac.utils.popen", return_value=content)
    assert mac == getmac.IfconfigWithIfaceArg().get(iface)


def test_ifconfigwithifacearg_edge_cases(mocker):
    # Test the test function
    mocker.patch("getmac.utils.check_command", return_value=False)
    assert getmac.IfconfigWithIfaceArg().test() is False
    utils.check_command.assert_called_once_with("ifconfig")

    cpe = CalledProcessError(cmd="ifconfig", returncode=1)
    mocker.patch("getmac.utils.popen", side_effect=cpe)
    assert getmac.IfconfigWithIfaceArg().get("eth0") is None

    cpe = CalledProcessError(cmd="ifconfig", returncode=255)
    mocker.patch("getmac.utils.popen", side_effect=cpe)
    with pytest.raises(CalledProcessError):
        getmac.IfconfigWithIfaceArg().get("eth0")


def test_arping_host_habets(benchmark, mocker, get_sample):
    content = get_sample("ubuntu_18.04/arping-habets.out")
    mocker.patch("getmac.utils.popen", return_value=content)

    ap = getmac.ArpingHost()
    ap._is_iputils = False
    ap.get("192.168.16.254")

    assert "00:50:56:e8:32:3c" == benchmark(ap.get, arg="192.168.16.254")


def test_arping_host_iputils(benchmark, mocker, get_sample):
    content = get_sample("ubuntu_18.04/arping-iputils.out")
    mocker.patch("getmac.utils.popen", return_value=content)

    ap = getmac.ArpingHost()
    ap.get("192.168.16.254")

    assert "00:50:56:E8:32:3C" == benchmark(ap.get, arg="192.168.16.254")


def test_arping_host_busybox(benchmark, mocker, get_sample):
    content = get_sample("WSL2_kali_2023.1/busybox_arping_-f_-c_1_172-29-16-1.out")
    mocker.patch("getmac.utils.popen", return_value=content)

    ap = getmac.ArpingHost()
    ap.get("172.29.16.1")

    assert "00:15:5d:20:f2:73" == benchmark(ap.get, arg="172.29.16.1")


def test_arping_host_habets_fallback(mocker, get_sample):
    # Habets arping fails on the iputils arguments, so the Habets arguments are used instead
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
    utils.popen.assert_called_with("arping", "-r -C 1 -c 1 192.168.16.254")


@pytest.mark.parametrize("output_type", ["str", "invalid_utf8"])
def test_arping_host_habets_fallback_output_types(mocker, get_sample, output_type):
    """The Habets fallback also works when the error output is a str or isn't valid UTF-8."""
    output = get_sample("WSL2_kali_2023.1/habets_arping_-f_-c_1_172-29-16-1.out")
    if output_type == "invalid_utf8":
        output = output.encode() + b"\xff\n"
    cpe = CalledProcessError(cmd="arping -f -c 1 192.168.16.254", returncode=1, output=output)
    habets_output = get_sample("ubuntu_18.04/arping-habets.out")
    mocker.patch("getmac.utils.popen", side_effect=[cpe, habets_output])

    ap = getmac.ArpingHost()
    assert ap.get("192.168.16.254") == "00:50:56:e8:32:3c"
    assert ap._is_iputils is False


def test_arping_host_busybox_error_no_fallback(mocker, get_sample):
    # BusyBox's usage error doesn't mention Habets, so the Habets arguments aren't tried
    cpe = CalledProcessError(
        cmd="arping --ridic",
        returncode=1,
        output=get_sample("WSL2_kali_2023.1/busbox_arping_--ridic.out").encode(),
    )
    mocker.patch("getmac.utils.popen", side_effect=cpe)

    ap = getmac.ArpingHost()
    assert ap.get("172.29.16.1") is None
    assert ap._is_iputils is True
    utils.popen.assert_called_once_with("arping", "-f -c 1 172.29.16.1")


def test_arping_host_edge_cases(mocker):
    # Test the test function
    mocker.patch("getmac.utils.check_command", return_value=False)
    assert getmac.ArpingHost().test() is False
    utils.check_command.assert_called_once_with("arping")

    # No output case in _call_habets()
    mocker.patch("getmac.utils.popen", return_value="")
    assert not getmac.ArpingHost()._call_habets("192.168.16.254")

    # Test somewhat complex fallback logic for Habets arping
    cpe = CalledProcessError(
        cmd="arping -f -c 1 192.0.2.1", output=b"invalid option", returncode=1
    )
    mocker.patch("getmac.utils.popen", side_effect=cpe)

    # Standard case
    mocker.patch(
        "getmac.getmac.ArpingHost._call_habets",
        return_value="00:50:56:e8:32:3c",
    )
    assert getmac.ArpingHost().get("192.168.16.254") == "00:50:56:e8:32:3c"

    # Exception handling case
    mocker.patch("getmac.getmac.ArpingHost._call_habets", side_effect=cpe)
    assert not getmac.ArpingHost().get("192.168.16.254")


@pytest.fixture
def windll(mocker):
    """
    Stands in for ``ctypes.windll``, which only exists on Windows. SendARP()
    succeeds, and writes a MAC to the buffer it's given (like the real one).
    """
    mac_buffer = ctypes.create_string_buffer(6)
    mocker.patch("ctypes.c_buffer", return_value=mac_buffer)
    windll = mocker.patch("ctypes.windll", create=True)
    windll.wsock32.inet_addr.return_value = 0x0A0200C0  # 192.0.2.10, in network byte order

    def _send_arp(*_args):
        mac_buffer.raw = b"\x00\x1a\x2b\x0c\x4d\xfe"
        return 0  # NO_ERROR

    windll.Iphlpapi.SendARP.side_effect = _send_arp
    return windll


def test_ctypes_host_test(mocker, windll):
    windll.wsock32.inet_addr.return_value = 0x0100007F
    assert getmac.CtypesHost().test() is True
    windll.wsock32.inet_addr.assert_called_once_with(b"127.0.0.1")

    # Not on Windows
    mocker.patch("ctypes.windll", None)
    assert getmac.CtypesHost().test() is False


def test_ctypes_host(windll):
    # Bytes less than 0x10 are zero-padded, e.g. "0c" not "c"
    assert getmac.CtypesHost().get("192.0.2.10") == "001a2b0c4dfe"
    windll.wsock32.inet_addr.assert_called_once_with(b"192.0.2.10")
    assert windll.Iphlpapi.SendARP.call_args[0][:2] == (0x0A0200C0, 0)

    # ERROR_BAD_NET_NAME, no ARP reply from the host
    windll.Iphlpapi.SendARP.side_effect = None
    windll.Iphlpapi.SendARP.return_value = 67
    assert getmac.CtypesHost().get("192.0.2.10") is None


def test_ctypes_host_hostname(mocker, windll):
    """If inet_addr() can't parse the argument, it's resolved as a hostname."""
    windll.wsock32.inet_addr.side_effect = [-1, 0x0A0200C0]  # INADDR_NONE, then 192.0.2.10
    mocker.patch("socket.gethostbyname", return_value="192.0.2.10")

    assert getmac.CtypesHost().get("myhost") == "001a2b0c4dfe"
    socket.gethostbyname.assert_called_once_with("myhost")
    # inet_addr() takes a char* (bytes), a str would be passed as a wchar_t*
    assert windll.wsock32.inet_addr.call_args_list == [
        mocker.call(b"myhost"),
        mocker.call(b"192.0.2.10"),
    ]
    assert windll.Iphlpapi.SendARP.call_args[0][0] == 0x0A0200C0


@pytest.mark.parametrize(
    ("mac", "iface", "sample_file"),
    [
        ("74-D4-35-E9-45-71", "Ethernet 3", "windows_10/ipconfig-all.out"),
        # Case is ignored, like on Windows
        ("74-D4-35-E9-45-71", "ethernet 3", "windows_10/ipconfig-all.out"),
        # The name must match the whole adapter name, not the start of one
        # ("Ethernet adapter Ethernet 3") or part of another adapter's description
        (None, "Ethernet", "windows_10/ipconfig-all.out"),
        (None, "Ethernet 33", "windows_10/ipconfig-all.out"),
        ("00-50-56-C0-00-08", "VMware Network Adapter VMnet8", "windows_10/ipconfig-all.out"),
        # Descriptions work too
        (
            "74-D4-35-E9-45-71",
            "Intel(R) Ethernet Connection I217-V",
            "windows_10/ipconfig-all.out",
        ),
        # Tunnel adapters have an 8-byte "Physical Address", which isn't a MAC. Their
        # names and characters like "*", "(" and "." in them are matched literally.
        (None, "Local Area Connection* 1", "windows_10/ipconfig-all.out"),
        (None, "Microsoft Teredo Tunneling Adapter", "windows_10/ipconfig-all.out"),
        (None, "Teredo", "windows_10/ipconfig-all.out"),
        (None, "Local Area Connection.. 1", "windows_10/ipconfig-all.out"),
        (None, "Ethernet (", "windows_10/ipconfig-all.out"),
    ],
)
def test_ipconfig_exe_samples(benchmark, mocker, get_sample, mac, iface, sample_file):
    mocker.patch("getmac.utils.popen", return_value=get_sample(sample_file))
    assert mac == benchmark(getmac.IpconfigExe().get, arg=iface)
    utils.popen.assert_called_with("ipconfig.exe", "/all")


@pytest.mark.parametrize(
    "label",
    [
        "Adresse physique . . . . . . . . . . .",  # French
        "Physikalische Adresse . . . . . . . . .",  # German
        "Dirección física . . . . . . . . . . . .",  # Spanish
    ],
)
def test_ipconfig_exe_translated_mac_label(mocker, get_sample, label):
    """
    The MAC is found when "Physical Address" is translated. There aren't any non-English
    samples yet, so this uses the English sample with the label replaced.
    """
    content = get_sample("windows_10/ipconfig-all.out")
    content = content.replace("Physical Address. . . . . . . . .", label)
    mocker.patch("getmac.utils.popen", return_value=content)

    assert getmac.IpconfigExe().get("Ethernet 3") == "74-D4-35-E9-45-71"
    assert getmac.IpconfigExe().get("Intel(R) Ethernet Connection I217-V") == "74-D4-35-E9-45-71"
    # The 8-byte address of a tunnel adapter still isn't a MAC
    assert getmac.IpconfigExe().get("Local Area Connection* 1") is None


def test_ipconfig_exe_no_physical_address(mocker, get_sample):
    """The start of the DHCPv6 client DUID (14 bytes) isn't mistaken for a MAC."""
    lines = get_sample("windows_10/ipconfig-all.out").splitlines(keepends=True)
    content = "".join(line for line in lines if "Physical Address" not in line)
    assert "DHCPv6 Client DUID" in content
    mocker.patch("getmac.utils.popen", return_value=content)

    assert getmac.IpconfigExe().get("Ethernet 3") is None


@pytest.mark.parametrize(
    ("mac", "iface"),
    [
        ("A0-36-BC-12-34-56", "Ethernet 7"),
        ("4C-03-4F-65-43-21", "Wi-Fi 2"),
        # Case is ignored, like on Windows
        ("4C-03-4F-65-43-21", "wi-fi 2"),
        # Names longer than 15 characters (the table format cuts them off)
        ("00-50-56-C0-00-01", "VMware Network Adapter VMnet1"),
        ("00-50-56-C0-00-08", "VMware Network Adapter VMnet8"),
        # Network adapters work too
        ("4C-03-4F-65-43-21", "Intel(R) Wi-Fi 6 AX201 160MHz"),
        ("00-50-56-C0-00-08", "VMware Virtual Ethernet Adapter for VMnet8"),
        # The name must match the whole connection name or network adapter
        (None, "Wi-Fi"),
        (None, "Ethernet"),
        (None, "Ethernet ("),
        # The header (when getmac.exe is run without /NH)
        (None, "Connection Name"),
    ],
)
def test_getmac_exe_samples(benchmark, mocker, get_sample, mac, iface):
    content = get_sample("windows_11/getmac_-V_-FO_CSV.out")
    mocker.patch("getmac.utils.popen", return_value=content)
    assert mac == benchmark(getmac.GetmacExe().get, arg=iface)
    utils.popen.assert_called_with("getmac.exe", "/NH /V /FO CSV")  # codespell:ignore fo


def test_getmac_exe_no_mac(mocker):
    # Disabled adapters don't have a MAC
    output = '"Ethernet","Intel(R) Ethernet Connection I217-V","N/A","Disconnected"\r\n'
    mocker.patch("getmac.utils.popen", return_value=output)
    assert getmac.GetmacExe().get("Ethernet") is None


@pytest.mark.parametrize(
    ("mac", "ip", "sample_file"),
    [
        # IPv4 uses "netsh int ipv4 show neigh"
        ("6a-d7-9a-29-2b-82", "10.0.0.1", "windows_10/netsh_int_ipv4_show_neigh.out"),
        ("78-28-ca-c4-66-fe", "10.0.0.175", "windows_10/netsh_int_ipv4_show_neigh.out"),
        (None, "10.0.0.17", "windows_10/netsh_int_ipv4_show_neigh.out"),
        (None, "0.0.1", "windows_10/netsh_int_ipv4_show_neigh.out"),
        # Unreachable entries have an all-zero MAC
        (None, "192.168.17.1", "windows_10/netsh_int_ipv4_show_neigh.out"),
        # IPv6 uses "netsh int ipv6 show neigh". Case is ignored.
        ("33-33-00-00-00-fb", "ff02::fb", "windows_10/netsh_int_ipv6_show_neigh.out"),
        ("33-33-00-00-00-fb", "FF02::FB", "windows_10/netsh_int_ipv6_show_neigh.out"),
        (None, "fe80::42b0:34ff:fe74:afdd", "windows_10/netsh_int_ipv6_show_neigh.out"),
        (None, "fe80::1", "windows_10/netsh_int_ipv6_show_neigh.out"),
    ],
)
def test_netsh_neighbors_samples(benchmark, mocker, get_sample, mac, ip, sample_file):
    mocker.patch("getmac.utils.popen", return_value=get_sample(sample_file))
    assert mac == benchmark(getmac.NetshNeighbors().get, arg=ip)
    version = "ipv6" if ":" in ip else "ipv4"
    utils.popen.assert_called_with("netsh.exe", f"int {version} show neigh")

    mocker.patch("getmac.utils.check_command", return_value=False)
    assert getmac.NetshNeighbors().test() is False
    utils.check_command.assert_called_once_with("netsh.exe")


def test_default_iface_netsh(benchmark, mocker, get_sample):
    content = get_sample("windows_10/netsh_int_ipv4_show_route.out")
    mocker.patch("getmac.utils.popen", return_value=content)
    # The default route goes through gateway 10.0.0.1, on interface 5 ("Ethernet 4")
    assert "Ethernet 4" == benchmark(getmac.DefaultIfaceNetsh().get)
    utils.popen.assert_called_with("netsh.exe", "int ipv4 show route")

    mocker.patch("getmac.utils.check_command", return_value=False)
    assert getmac.DefaultIfaceNetsh().test() is False
    utils.check_command.assert_called_once_with("netsh.exe")


@pytest.mark.parametrize(
    ("expected", "routes"),
    [
        # The lowest metric wins, and an on-link default route has the interface name
        (
            "Wi-Fi",
            [
                "No       Manual    25   0.0.0.0/0                   5  10.0.0.1",
                "No       Manual    10   0.0.0.0/0                  12  Wi-Fi",
                "No       System    256  10.0.0.0/24                 5  Ethernet 4",
            ],
        ),
        (
            "Ethernet 4",
            [
                "No       Manual    10   0.0.0.0/0                   5  10.0.0.1",
                "No       Manual    25   0.0.0.0/0                  12  Wi-Fi",
                "No       System    256  10.0.0.0/24                 5  Ethernet 4",
            ],
        ),
        # No default route, or no name for its interface
        (None, ["No       System    256  10.0.0.0/24                 5  Ethernet 4"]),
        (None, ["No       Manual    0    0.0.0.0/0                   5  10.0.0.1"]),
    ],
)
def test_default_iface_netsh_routes(mocker, expected, routes):
    header = (
        "\r\nPublish  Type      Met  Prefix                    Idx  Gateway/Interface Name\r\n"
        "-------  --------  ---  ------------------------  ---  ------------------------\r\n"
    )
    mocker.patch("getmac.utils.popen", return_value=header + "\r\n".join(routes) + "\r\n")
    assert getmac.DefaultIfaceNetsh().get() == expected


def test_getmac_exe_error(mocker):
    cpe = CalledProcessError(cmd="getmac.exe /NH /V /FO CSV", returncode=2)  # codespell:ignore fo
    mocker.patch("getmac.utils.popen", side_effect=cpe)
    inst = getmac.GetmacExe()
    assert inst.get("Ethernet") is None
    assert inst.unusable is True


def test_windows_10_iface_wmic(benchmark, mocker, get_sample):
    content = get_sample("windows_10/wmic_nic.out")
    mocker.patch("getmac.utils.popen", return_value=content)
    assert "00:FF:17:15:F8:C8" == benchmark(getmac.WmicExe().get, arg="Ethernet 3")


@pytest.mark.parametrize(
    ("mac", "ip", "sample_file"),
    [
        ("78-28-ca-c4-66-fe", "10.0.0.175", "windows_10/arp_-a_10.0.0.175.out"),
        # French Windows
        ("00-80-0c-07-ae-d3", "192.168.0.1", "third_party/glpi_agent/generic/arp/win32"),
        # French Windows, "No ARP Entries Found."
        (None, "192.168.0.1", "third_party/glpi_agent/generic/arp/none"),
    ],
)
def test_arpexe_samples(benchmark, mocker, get_sample, mac, ip, sample_file):
    content = get_sample(sample_file)
    mocker.patch("getmac.utils.popen", return_value=content)
    assert mac == benchmark(getmac.ArpExe().get, arg=ip)

    mocker.patch("getmac.utils.check_command", return_value=False)
    assert getmac.ArpExe().test() is False
    utils.check_command.assert_called_once_with("arp.exe")


def test_openbsd_get_default_iface(benchmark, mocker, get_sample):
    content = get_sample("openbsd_6/route_nq_show_inet_gateway_priority_1.out")
    mocker.patch("getmac.utils.popen", return_value=content)
    assert "em0" == benchmark(getmac.DefaultIfaceOpenBsd().get)

    mocker.patch("getmac.utils.popen", return_value="")
    assert not getmac.DefaultIfaceOpenBsd().get()

    mocker.patch("getmac.utils.check_command", return_value=False)
    assert getmac.DefaultIfaceOpenBsd().test() is False
    utils.check_command.assert_called_once_with("route")


def test_openbsd_remote(benchmark, mocker, get_sample):
    content = get_sample("openbsd_6/arp_an.out")
    mocker.patch("getmac.utils.popen", return_value=content)
    assert "52:54:00:12:35:02" == benchmark(getmac.ArpOpenbsd().get, arg="10.0.2.2")
    assert "52:54:00:12:35:03" == getmac.ArpOpenbsd().get("10.0.2.3")
    assert "08:00:27:18:64:56" == getmac.ArpOpenbsd().get("10.0.2.15")

    mocker.patch("getmac.utils.check_command", return_value=False)
    assert getmac.ArpOpenbsd().test() is False
    utils.check_command.assert_called_once_with("arp")


def test_freebsd_get_default_iface(benchmark, mocker, get_sample):
    content = get_sample("freebsd11/netstat_r.out")
    mocker.patch("getmac.utils.popen", return_value=content)
    assert "em0" == benchmark(getmac.DefaultIfaceFreeBsd().get)

    mocker.patch("getmac.utils.check_command", return_value=False)
    assert getmac.DefaultIfaceFreeBsd().test() is False
    utils.check_command.assert_called_once_with("netstat")


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
    mocker.patch("getmac.utils.popen", return_value=content)
    assert mac == benchmark(getmac.ArpFreebsd().get, arg=ip)

    assert not getmac.ArpFreebsd().get("")
    assert not getmac.ArpFreebsd().get("10.")
    assert not getmac.ArpFreebsd().get("10.10.10.10")
    assert not getmac.ArpFreebsd().get(mac)
    assert not getmac.ArpFreebsd().get("em0")

    mocker.patch("getmac.utils.check_command", return_value=False)
    assert getmac.ArpFreebsd().test() is False
    utils.check_command.assert_called_once_with("arp")


@pytest.mark.parametrize(
    ("mac", "ip", "sample_file"),
    [
        (
            "00:50:56:f1:4c:50",
            "192.168.16.2",
            "ubuntu_18.04/cat_proc-net-arp.out",
        ),
        ("00:50:56:e1:a8:4a", "192.168.16.2", "ubuntu_18.10/proc_net_arp.out"),
        (
            "00:50:56:e8:32:3c",
            "192.168.16.254",
            "ubuntu_18.10/proc_net_arp.out",
        ),
        ("00:50:56:c0:00:0a", "192.168.95.1", "ubuntu_18.10/proc_net_arp.out"),
        ("52:55:0a:00:02:02", "10.0.2.2", "android_6/cat_proc-net-arp.out"),
        (
            "02:00:00:00:01:00",
            "192.168.232.1",
            "android_9/cat_proc-net-arp.out",
        ),
        (
            "8e:8f:aa:c9:d2:8b",
            "192.168.200.1",
            "android_9/cat_proc-net-arp.out",
        ),
        # Same MAC as the incomplete 192.168.0.46 entry above it (issue #76)
        ("02:00:00:00:00:47", "192.168.0.47", "ubuntu_20.04/cat_proc-net-arp.out"),
        # Synthetic sample, rows formatted the same way as the kernel's
        # arp_format_neigh_entry() and arp_format_pneigh_entry() (net/ipv4/arp.c)
        (
            "02:00:00:00:00:10",
            "192.0.2.10",
            "linux_synthetic/cat_proc-net-arp_flags.out",
        ),
        # Permanent entry (Flags 0x6), listed after 192.0.2.10
        (
            "02:00:00:00:00:01",
            "192.0.2.1",
            "linux_synthetic/cat_proc-net-arp_flags.out",
        ),
        # Incomplete entry on eth0, complete entry for the same IP on eth1
        (
            "02:00:00:00:00:22",
            "192.0.2.2",
            "linux_synthetic/cat_proc-net-arp_flags.out",
        ),
    ],
)
def test_arpfile_samples(benchmark, mocker, get_sample, mac, ip, sample_file):
    content = get_sample(sample_file)
    mocker.patch("getmac.utils.read_file", return_value=content)
    assert mac == benchmark(getmac.ArpFile().get, arg=ip)

    assert not getmac.ArpFile().get("0.0.0.0")
    assert not getmac.ArpFile().get("104.0.0.0")
    assert not getmac.ArpFile().get("")
    assert not getmac.ArpFile().get(mac)

    mocker.patch("getmac.utils.read_file", return_value=None)
    inst = getmac.ArpFile()
    assert not inst.get(ip)
    assert inst.unusable is True

    mocker.patch("getmac.utils.read_file", return_value="")
    assert not getmac.ArpFile().get(ip)

    mocker.patch("getmac.utils.check_path", return_value=False)
    assert getmac.ArpFile().test() is False
    # The path can be changed with the ARP_PATH environment variable
    utils.check_path.assert_called_once_with(getmac.ArpFile._path)


@pytest.mark.parametrize(
    ("ip", "sample_file"),
    [
        # Entries with Flags 0x0 are incomplete or failed, and must be ignored
        # even if they still have a (stale) MAC (issue #76)
        ("192.168.0.46", "ubuntu_20.04/cat_proc-net-arp.out"),
        ("192.168.95.254", "ubuntu_18.10/proc_net_arp.out"),
        ("104.198.143.177", "ubuntu_18.10/proc_net_arp.out"),
        ("192.0.2.4", "linux_synthetic/cat_proc-net-arp_flags.out"),
        # Proxy ARP entry (Flags 0xc, published), it doesn't have a real MAC
        ("192.0.2.3", "linux_synthetic/cat_proc-net-arp_flags.out"),
        # Must match the whole IP, not just the end of it
        ("92.168.16.2", "ubuntu_18.04/cat_proc-net-arp.out"),
        ("2.0.2.1", "linux_synthetic/cat_proc-net-arp_flags.out"),
        # Not in the table at all
        ("192.168.0.48", "ubuntu_20.04/cat_proc-net-arp.out"),
        ("192.0.2.5", "linux_synthetic/cat_proc-net-arp_flags.out"),
    ],
)
def test_arpfile_ignored_entries(mocker, get_sample, ip, sample_file):
    mocker.patch("getmac.utils.read_file", return_value=get_sample(sample_file))
    assert getmac.ArpFile().get(ip) is None


@pytest.mark.parametrize(
    ("mac", "ip", "sample_file"),
    [
        (
            "00:50:56:f1:4c:50",
            "192.168.16.2",
            "ubuntu_18.04/ip_neighbor_show_192-168-16-2.out",
        ),
        (
            "00:50:56:f1:4c:50",
            "192.168.16.2",
            "ubuntu_18.04/ip_neighbor_show.out",
        ),
        (
            "52:55:0a:00:02:02",
            "10.0.2.2",
            "android_6/ip_neighbor_show_10.0.2.2.out",
        ),
        ("52:55:0a:00:02:02", "10.0.2.2", "android_6/ip_neighbor.out"),
        ("52:56:00:00:00:02", "fe80::2", "android_6/ip_neighbor.out"),
        ("8e:8f:aa:c9:d2:8b", "192.168.200.1", "android_9/ip_neighbor.out"),
        (
            "8e:8f:aa:c9:d2:8b",
            "fe80::8c8f:aaff:fec9:d28b",
            "android_9/ip_neighbor.out",
        ),
        (
            "00:0d:b9:37:2b:c2",
            "10.0.10.1",
            "third_party/glpi_agent/generic/arp/linux-ip-neighbor",
        ),
    ],
)
def test_ipneighborshow_samples(benchmark, mocker, get_sample, mac, ip, sample_file):
    content = get_sample(sample_file)
    mocker.patch("getmac.utils.popen", return_value=content)

    assert mac == benchmark(getmac.IpNeighborShow().get, arg=ip)
    assert getmac.IpNeighborShow().get("bad") is None


def test_ipneighborshow_edge_cases(mocker):
    # Test the test function
    mocker.patch("getmac.utils.check_command", return_value=False)
    assert getmac.IpNeighborShow().test() is False
    utils.check_command.assert_called_once_with("ip")

    mocker.patch("getmac.utils.popen", return_value="")
    assert not getmac.IpNeighborShow().get("192.168.16.2")


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
    mocker.patch("getmac.utils.popen", return_value=content)

    assert mac == benchmark(getmac.NetstatIface().get, arg=iface)
    assert getmac.NetstatIface().get("lo") is None
    assert getmac.NetstatIface().get("ens") is None
    assert getmac.NetstatIface().get("ens3") is None
    assert getmac.NetstatIface().get("ens333") is None
    assert getmac.NetstatIface().get("docker") is None
    assert getmac.NetstatIface().get("eth") is None
    assert getmac.NetstatIface().get("eth00") is None
    # The end of another interface's name doesn't match it
    assert getmac.NetstatIface().get("h0") is None
    assert getmac.NetstatIface().get("Kernel") is None
    assert getmac.NetstatIface().get("e") is None
    # "." isn't a wildcard
    assert getmac.NetstatIface().get(iface[:-1] + ".") is None


def test_netstatiface_no_mac_before_next_interface(mocker, get_sample):
    """An interface without a MAC doesn't get the MAC of the interface after it."""
    content = get_sample("ubuntu_18.04/netstat_iae.out")
    lo = content[content.index("lo:") :]
    mocker.patch("getmac.utils.popen", return_value=lo + "\n" + content)
    assert getmac.NetstatIface().get("lo") is None


def test_netstatiface_edge_cases(mocker):
    # Test the test function
    mocker.patch("getmac.utils.check_command", return_value=False)
    assert getmac.NetstatIface().test() is False
    utils.check_command.assert_called_once_with("netstat")

    mocker.patch("getmac.utils.popen", return_value=None)
    assert getmac.NetstatIface().get("eth0") is None
    mocker.patch("getmac.utils.popen", return_value=" ")
    assert getmac.NetstatIface().get("eth0") is None


@pytest.mark.parametrize(
    ("expected_mac", "iface_arg", "sample_file"),
    [
        ("b4:2e:99:36:1e:33", "eth0", "WSL_ubuntu_18.04/ip_link.out"),
        ("b4:2e:99:35:1e:86", "eth3", "WSL_ubuntu_18.04/ip_link.out"),
        ("00:15:5d:83:d9:0a", "eth8", "WSL_ubuntu_18.04/ip_link.out"),
        (None, "lo", "WSL_ubuntu_18.04/ip_link.out"),
        ("00:ff:36:20:68:56", "eth15", "WSL_ubuntu_18.04/ip_link.out"),
        (None, "eth16", "WSL_ubuntu_18.04/ip_link.out"),
        (None, "eth", "WSL_ubuntu_18.04/ip_link.out"),
        # The end of another interface's name doesn't match it, and "." isn't a wildcard
        (None, "h0", "WSL_ubuntu_18.04/ip_link.out"),
        (None, "eth.", "WSL_ubuntu_18.04/ip_link.out"),
        ("0a:15:3d:6f:80:b5", "dummy0", "android_6.0.1_no_root__ip_link.txt"),
        ("00:0a:f5:52:24:04", "wlan0", "android_6.0.1_no_root__ip_link.txt"),
        ("02:0a:f5:52:24:04", "p2p0", "android_6.0.1_no_root__ip_link.txt"),
        # Cellular data interfaces ("link/[530]") don't have a MAC
        (None, "rmnet0", "android_6.0.1_no_root__ip_link.txt"),
        (None, "rmnet_data0", "android_6.0.1_no_root__ip_link.txt"),
        (None, "lo", "android_6.0.1_no_root__ip_link.txt"),
        ("00:50:56:9a:cb:a4", "ens160", "third_party/facter/ip_link_show"),
        (None, "lo", "third_party/facter/ip_link_show"),
    ],
)
def test_ip_link_iface_no_iface_arg(
    benchmark, mocker, get_sample, expected_mac, iface_arg, sample_file
):
    # Code path for older versions of "ip link" that don't accept an interface
    # argument, which parses the output of "ip link" (all interfaces) instead
    mocker.patch("getmac.getmac.IpLinkIface._tested_arg", True)
    mocker.patch("getmac.getmac.IpLinkIface._iface_arg", False)
    content = get_sample(sample_file)
    mocker.patch("getmac.utils.popen", return_value=content)
    assert expected_mac == benchmark(getmac.IpLinkIface().get, arg=iface_arg)
    utils.popen.assert_called_with("ip", "link")


@pytest.mark.parametrize(
    ("mac", "iface", "sample_file"),
    [
        ("08:00:27:12:33:44", "eth0", "ubuntu_18.04/ip_link_show_eth0.out"),
        ("00:0c:29:b5:72:37", "ens33", "ubuntu_18.04/ip_link_list.out"),
        ("00:0c:29:b5:72:37", "ens33", "ubuntu_18.04/ip_link.out"),
        ("74:d4:35:e9:45:71", "eth0", "ip_link_list.out"),
        ("52:54:00:12:34:56", "eth0", "android_6/ip_link.out"),
        ("52:54:00:12:34:56", "eth0", "android_6/ip_link_show_eth0.out"),
        ("46:37:e2:ae:b8:7f", "radio0@if10", "android_9/ip_link.out"),
    ],
)
def test_iplinkiface_samples(benchmark, mocker, get_sample, mac, iface, sample_file):
    content = get_sample(sample_file)
    mocker.patch("getmac.utils.popen", return_value=content)
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


def test_ip_link_iface_edge_cases(mocker, get_sample):
    # Test the test function
    mocker.patch("getmac.utils.check_command", return_value=False)
    assert getmac.IpLinkIface().test() is False
    utils.check_command.assert_called_once_with("ip")

    # Test the exception handling works for old-style ip link
    content = get_sample("ip_link_list.out")
    cpe = CalledProcessError(cmd="", returncode=255)
    mocker.patch("getmac.utils.popen", side_effect=[cpe, content])
    except_method = getmac.IpLinkIface()
    assert "74:d4:35:e9:45:71" == except_method.get("eth0")


@pytest.mark.parametrize(
    ("expected_iface", "sample_file"),
    [
        ("ens33", "ubuntu_18.04/route_-n.out"),
        ("eth0", "WSL_ubuntu_18.04/route_-n.out"),
        ("eth0", "android_6/route_-n.out"),
    ],
)
def test_default_iface_route_command(benchmark, mocker, get_sample, expected_iface, sample_file):
    content = get_sample(sample_file)
    mocker.patch("getmac.utils.popen", return_value=content)
    assert expected_iface == benchmark(getmac.DefaultIfaceRouteCommand().get)

    mocker.patch("getmac.utils.popen", return_value="")
    assert not getmac.DefaultIfaceRouteCommand().get()

    mocker.patch("getmac.utils.popen", return_value="0.0.0.0 ")
    assert not getmac.DefaultIfaceRouteCommand().get()


@pytest.mark.parametrize(
    ("iface", "sample_file"),
    [
        ("ens33", "ubuntu_18.10/proc_net_route.out"),
        ("eth0", "android_6/cat_proc-net-route.out"),
        (None, "android_9/cat_proc-net-route.out"),
        ("ens160", "third_party/facter/proc_net_route"),
        # Only the header line, no routes
        (None, "third_party/facter/proc_net_route_empty"),
    ],
)
def test_defaultifacelinuxroutefile_samples(benchmark, mocker, get_sample, iface, sample_file):
    content = get_sample(sample_file)
    mocker.patch("getmac.utils.read_file", return_value=content)
    assert benchmark(getmac.DefaultIfaceLinuxRouteFile().get) == iface


def test_defaultifacelinuxroutefile(mocker):
    # Test the test function
    mocker.patch("getmac.utils.check_path", return_value=False)
    assert getmac.DefaultIfaceLinuxRouteFile().test() is False
    utils.check_path.assert_called_once_with("/proc/net/route")

    mocker.patch("getmac.utils.read_file", return_value=None)
    assert getmac.DefaultIfaceLinuxRouteFile().get() is None

    mocker.patch("getmac.utils.read_file", return_value="")
    assert getmac.DefaultIfaceLinuxRouteFile().get() is None


@pytest.mark.parametrize(
    ("iface", "sample_file"),
    [
        ("ens33", "ubuntu_18.04/ip_route_list_0slash0.out"),
        ("eth0", "WSL_ubuntu_18.04/ip_route_list_0slash0.out"),
        ("eth0", "android_6/ip_route_list_0slash0.out"),
        ("wlan0", "third_party/glpi_agent/linux/ip/default-gateway-1"),
        # Two default routes, the first one has the lowest metric
        ("eth0", "third_party/glpi_agent/linux/ip/default-gateway-2"),
        # No "proto" after the interface name
        ("ens193", "third_party/glpi_agent/linux/ip/default-gateway-3"),
    ],
)
def test_defaultifaceiproute_samples(benchmark, mocker, get_sample, iface, sample_file):
    content = get_sample(sample_file)
    mocker.patch("getmac.utils.popen", return_value=content)
    assert iface == benchmark(getmac.DefaultIfaceIpRoute().get)


@pytest.mark.parametrize(
    ("iface", "output"),
    [
        ("eth0", "default via 10.0.0.1 dev eth0 metric 100\n"),
        ("wg0", "default dev wg0 scope link\n"),
        # Route with multiple next hops (multipath), "proto" is before "dev"
        (
            "eth0",
            (
                "default proto static metric 100\n"
                "\tnexthop via 10.0.0.1 dev eth0 weight 1\n"
                "\tnexthop via 10.0.0.2 dev eth1 weight 1\n"
            ),
        ),
    ],
)
def test_defaultifaceiproute_without_proto(mocker, iface, output):
    mocker.patch("getmac.utils.popen", return_value=output)
    assert getmac.DefaultIfaceIpRoute().get() == iface


def test_defaultifaceiproute(mocker):
    mocker.patch("getmac.utils.popen", return_value=None)
    assert getmac.DefaultIfaceIpRoute().get() is None

    mocker.patch("getmac.utils.popen", return_value="")
    assert getmac.DefaultIfaceIpRoute().get() is None

    mocker.patch("getmac.utils.popen", return_value="asdfalksj3")
    assert getmac.DefaultIfaceIpRoute().get() is None


@pytest.mark.parametrize(
    ("iface", "sample_file"),
    [
        ("en0", "macos_10.12.6/route_-n_get_default.out"),
        ("em0", "freebsd11/route_get_default.out"),
        # Solaris (uses the "other" platform methods)
        ("net0", "third_party/facter/route_n_get_default"),
    ],
)
def test_defaultifaceroutegetcommand_samples(benchmark, mocker, get_sample, iface, sample_file):
    content = get_sample(sample_file)
    mocker.patch("getmac.utils.popen", return_value=content)
    assert iface == benchmark(getmac.DefaultIfaceRouteGetCommand().get)

    mocker.patch("getmac.utils.popen", return_value=None)
    assert not getmac.DefaultIfaceRouteGetCommand().get()

    mocker.patch("getmac.utils.popen", return_value="")
    assert not getmac.DefaultIfaceRouteGetCommand().get()

    # test with bad input (hit the except indexerror case)
    mocker.patch("getmac.utils.popen", return_value="interface:")
    assert not getmac.DefaultIfaceRouteGetCommand().get()

    mocker.patch("getmac.utils.check_command", return_value=False)
    assert getmac.DefaultIfaceRouteGetCommand().test() is False
    utils.check_command.assert_called_once_with("route")


# NOTE: Darwin and Solaris will return MACs without leading zeroes,
# e.g. "58:6d:8f:7:c9:94" instead of "58:6d:8f:07:c9:94"
#
# It makes more sense to me to just handle the weird mac here
# in the test instead of adding redundant logic for cleaning
# the result to the method. "raw_mac" is what the method returns,
# and "mac" is the result after cleaning.
@pytest.mark.parametrize(
    ("mac", "raw_mac", "ip", "sample_file"),
    [
        ("58:6d:8f:07:c9:94", "58:6d:8f:7:c9:94", "192.168.1.1", "OSX/arp_-a.out"),
        ("58:6d:8f:07:c9:94", "58:6d:8f:7:c9:94", "192.168.1.1", "OSX/arp_-an.out"),
        ("52:54:00:12:35:02", "52:54:0:12:35:2", "10.0.2.2", "macos_10.12.6/arp_-an.out"),
        ("52:54:00:12:35:03", "52:54:0:12:35:3", "10.0.2.3", "macos_10.12.6/arp_-an.out"),
        ("01:00:5e:00:00:fb", "1:0:5e:0:0:fb", "224.0.0.251", "macos_10.12.6/arp_-an.out"),
        ("52:54:00:12:35:03", "52:54:0:12:35:3", "10.0.2.3", "macos_10.12.6/arp_10.0.2.3.out"),
        ("00:50:56:f1:4c:50", "00:50:56:f1:4c:50", "192.168.16.2", "ubuntu_18.04/arp_-a.out"),
        ("00:50:56:f1:4c:50", "00:50:56:f1:4c:50", "192.168.16.2", "ubuntu_18.04/arp_-an.out"),
        (
            "00:8d:b9:37:4a:c2",
            "00:8d:b9:37:4a:c2",
            "192.168.0.3",
            "third_party/glpi_agent/generic/arp/linux",
        ),
        ("52:54:00:12:35:02", "52:54:00:12:35:02", "10.0.2.2", "freebsd11/arp_10-0-2-2.out"),
        ("52:54:00:12:35:02", "52:54:00:12:35:02", "10.0.2.2", "netbsd8.2/arp_10-0-2-2.out"),
        ("52:54:00:12:35:03", "52:54:00:12:35:03", "10.0.2.3", "netbsd8.2/arp_a.out"),
        ("52:54:00:12:35:02", "52:54:0:12:35:2", "10.0.2.2", "solaris10/arp_10-0-2-2.out"),
        # Linux net-tools "arp <ip>" prints a table instead of "? (ip) at mac"
        ("02:42:3a:5c:7e:91", "02:42:3a:5c:7e:91", "172.17.0.1", "debian_13/arp_172-17-0-1.out"),
    ],
)
def test_arp_various_args_samples(benchmark, mocker, get_sample, mac, raw_mac, ip, sample_file):
    content = get_sample(sample_file)
    mocker.patch("getmac.utils.popen", return_value=content)
    if "OSX" in sample_file or "macos" in sample_file:
        mocker.patch.object(consts, "DARWIN", True)
    elif "solaris" in sample_file:
        mocker.patch.object(consts, "SOLARIS", True)

    result = benchmark(getmac.ArpVariousArgs().get, arg=ip)
    assert result == raw_mac
    assert mac == utils.clean_mac(result)


def test_arp_various_args_edge_cases(mocker, get_sample):
    assert not getmac.ArpVariousArgs().get("")

    cpe = CalledProcessError(cmd="arp", returncode=1)
    mocker.patch("getmac.utils.popen", side_effect=cpe)
    assert getmac.ArpVariousArgs().get("192.0.2.1") is None

    # Not sure if IP is required on Ubuntu 18, this is just for purposes of testing
    mocker.patch(
        "getmac.utils.popen",
        return_value=get_sample("ubuntu_18.04/arp_-an.out"),
    )
    inst = getmac.ArpVariousArgs()
    inst._args_tested = True
    inst._good_pair = ("-an", True)
    assert inst.get("192.168.16.2") == "00:50:56:f1:4c:50"


@pytest.mark.parametrize(
    ("ip", "sample_file"),
    [
        # Incomplete entry: the host didn't reply (yet)
        ("172.17.0.250", "debian_13/arp_172-17-0-250.out"),
        ("172.17.0.25", "debian_13/arp_172-17-0-250.out"),
        ("72.17.0.1", "debian_13/arp_172-17-0-1.out"),
        ("10.11.12.13", "debian_13/arp_10-11-12-13.out"),
    ],
)
def test_arp_various_args_linux_no_entry(mocker, get_sample, ip, sample_file):
    mocker.patch("getmac.utils.popen", return_value=get_sample(sample_file))
    assert getmac.ArpVariousArgs().get(ip) is None


def test_sys_iface_file(mocker):
    mocker.patch("getmac.utils.read_file", return_value="00:0c:29:b5:72:37\n")
    assert getmac.SysIfaceFile().get("ens33") == "00:0c:29:b5:72:37\n"

    mocker.patch("getmac.utils.read_file", return_value=None)
    assert getmac.SysIfaceFile().get("ens33") is None

    mocker.patch("getmac.utils.check_path", return_value=False)
    assert getmac.SysIfaceFile().test() is False
    utils.check_path.assert_called_once_with("/sys/class/net/")


@pytest.mark.parametrize(
    ("mac", "iface", "sample_file"),
    [("52:54:00:12:34:56", "eth0", "android_6/cat_sys-class-net-eth0-address.out")],
)
def test_sys_iface_file_samples(mocker, get_sample, mac, iface, sample_file):
    mocker.patch("getmac.utils.read_file", return_value=get_sample(sample_file))
    # The file has a trailing newline, get_mac_address() cleans it up
    assert mac == utils.clean_mac(getmac.SysIfaceFile().get(iface))
    utils.read_file.assert_called_once_with(f"/sys/class/net/{iface}/address")


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
    # The socket is closed when it's done
    m.return_value.__exit__.assert_called_once()


@pytest.mark.skipif(
    platform.system() != "Linux",
    reason="Can't reliably mock fcntl on non-Linux platforms",
)
def test_fcntl_iface_no_such_device(mocker):
    """The socket is closed even if the ioctl fails, e.g. for an interface that doesn't exist."""
    mocker.patch("fcntl.ioctl", side_effect=OSError(errno.ENODEV, "No such device"))
    m = mocker.patch("socket.socket")
    with pytest.raises(OSError, match="No such device"):
        getmac.FcntlIface().get("nope0")
    m.return_value.__exit__.assert_called_once()


def test_fcntl_iface_test(mocker):
    assert getmac.FcntlIface().test() is (platform.system() != "Windows")

    # fcntl can't be imported on Windows
    mocker.patch.dict(sys.modules, {"fcntl": None})
    assert getmac.FcntlIface().test() is False


@pytest.mark.parametrize(
    ("mac", "iface", "sample_file"),
    [
        # hpux: lanscan -iap
        (
            "00:17:A4:77:08:A4",
            "lan1",
            "third_party/glpi_agent/hpux/lanscan/hpux",
        ),
        (
            "00:17:A4:77:08:A2",
            "lan6",
            "third_party/glpi_agent/hpux/lanscan/hpux",
        ),
        (
            "00:17:A4:77:08:EA",
            "snap31",
            "third_party/glpi_agent/hpux/lanscan/hpux",
        ),
        (
            "00:00:00:00:00:00",
            "lan901",
            "third_party/glpi_agent/hpux/lanscan/hpux",
        ),
        (
            "00:00:00:00:00:00",
            "lan904",
            "third_party/glpi_agent/hpux/lanscan/hpux",
        ),
        # hpux1: lanscan -iap
        (
            "00:16:35:3E:AC:5C",
            "lan0",
            "third_party/glpi_agent/hpux/lanscan/hpux1",
        ),
        # hpux2: lanscan -iap
        (
            "00:16:35:3E:AC:44",
            "lan0",
            "third_party/glpi_agent/hpux/lanscan/hpux2",
        ),
        (
            "00:16:35:3E:AC:45",
            "lan1",
            "third_party/glpi_agent/hpux/lanscan/hpux2",
        ),
    ],
)
def test_lanscan_iface_samples(benchmark, mocker, get_sample, mac, iface, sample_file):
    content = get_sample(sample_file)
    mocker.patch("getmac.utils.popen", return_value=content)

    assert mac == benchmark(getmac.LanscanIface().get, arg=iface)

    assert not getmac.LanscanIface().get("lo0")
    assert not getmac.LanscanIface().get("lan")
    assert not getmac.LanscanIface().get("lan100")
    assert not getmac.LanscanIface().get("lan90")


def test_lanscan_iface_edge_cases(mocker):
    mocker.patch("getmac.utils.check_command", return_value=False)
    assert getmac.LanscanIface().test() is False
    utils.check_command.assert_called_once_with("lanscan")

    mocker.patch("getmac.utils.popen", return_value="")
    assert not getmac.LanscanIface().get("lan0")
    utils.popen.assert_called_once_with("lanscan", "-ai")
