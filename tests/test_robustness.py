# SPDX-FileCopyrightText: 2017-2026 Christopher Goes
# SPDX-License-Identifier: MIT

"""
Tests for how getmac copes with odd command output, files and settings.

A lookup returns :obj:`None` instead of a MAC that isn't the right one, and a single
odd value doesn't make a method raise (a method that raises isn't used again for the
rest of the process).
"""

import os
import shlex
import sys

import pytest

from getmac import getmac, utils
from getmac.variables import consts, gvars, settings

MAC = "00:11:22:33:44:55"


@pytest.mark.skipif(sys.platform == "win32", reason="Uses a named pipe")
def test_read_file_only_reads_regular_files(tmp_path):
    """A named pipe would wait forever, and a device could have no end."""
    os.mkfifo(str(tmp_path / "pipe"))

    assert utils.read_file(str(tmp_path / "pipe")) is None
    assert utils.read_file(os.devnull) is None
    assert utils.read_file(str(tmp_path)) is None


def test_read_file_bytes_that_are_not_utf8(tmp_path):
    """
    A name that isn't UTF-8 (Linux allows any bytes in an interface name) doesn't make
    the whole file unreadable, which would make the method fail and be removed.
    """
    arp = tmp_path / "arp"
    arp.write_bytes(
        b"IP address       HW type     Flags       HW address            Mask     Device\n"
        b"192.0.2.9        0x1         0x2         02:00:00:00:00:09     *        x\xff\xfe\n"
        b"192.0.2.1        0x1         0x2         02:00:00:00:00:01     *        eth0\n"
    )
    data = utils.read_file(str(arp))
    assert data is not None
    assert "02:00:00:00:00:01" in data


def test_read_file_has_a_size_limit(mocker, tmp_path):
    mocker.patch.object(utils, "_MAX_FILE_SIZE", 10)
    (tmp_path / "big").write_text("x" * 1000)

    assert utils.read_file(str(tmp_path / "big")) == "x" * 10


@pytest.mark.skipif(sys.platform == "win32", reason="The venv launcher keeps the pipe open")
def test_commands_dont_get_standard_input(mocker):
    """A command can't read (or wait for) the standard input of the program using getmac."""
    mocker.patch.object(consts, "WINDOWS", False)
    script = "import sys; print(repr(sys.stdin.read()))"

    assert utils.call_proc(sys.executable, "-c " + shlex.quote(script)).strip() == "''"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (15, 15.0),
        (0.5, 0.5),
        (0, None),
        (-1, None),
        (None, None),
        (float("inf"), None),
        (float("nan"), None),
        (1e308, None),
        ("15", None),
        (True, None),
    ],
)
def test_timeout_settings_are_checked(mocker, value, expected):
    """A timeout that can't be waited for means no timeout, and isn't an error."""
    assert utils._seconds_or_none(value) == expected

    mocker.patch.object(settings, "COMMAND_TIMEOUT", value)
    mocker.patch.object(consts, "WINDOWS", False)
    check_output = mocker.patch("subprocess.check_output", return_value=b"")
    utils.call_proc("/sbin/cmd", "")
    assert check_output.call_args.kwargs["timeout"] == expected


@pytest.mark.parametrize("value", [float("inf"), float("nan"), -1, "5"])
def test_arp_timeout_that_cant_be_waited_for(mocker, value):
    """ARP_TIMEOUT of infinity or "not a number" used to wait forever."""
    mocker.patch.object(settings, "ARP_TIMEOUT", value)
    get_by_method = mocker.patch("getmac.getmac.get_by_method", return_value=None)
    sleep = mocker.patch("time.sleep")

    assert getmac._lookup_host("ip4", "192.0.2.1", True, wait=True) is None
    get_by_method.assert_called_once()
    sleep.assert_not_called()


@pytest.mark.parametrize("kwargs", [{"ip6": "fe80::1"}, {"ip": "192.0.2.1"}])
def test_socket_that_cant_be_created_is_not_an_error(mocker, kwargs):
    """E.g. IPv6 turned off in the kernel: socket.has_ipv6 is still True."""
    mocker.patch("socket.has_ipv6", True)
    mocker.patch("socket.socket", side_effect=OSError(97, "Address family not supported"))
    mocker.patch("getmac.getmac.METHOD_CACHE", dict.fromkeys(getmac.METHOD_CACHE))
    mocker.patch("getmac.getmac.FALLBACK_CACHE", {k: [] for k in getmac.FALLBACK_CACHE})
    mocker.patch("getmac.getmac.get_by_method", return_value=None)
    mocker.patch("getmac.getmac.initialize_method_cache")
    mocker.patch("getmac.getmac.get_instance_from_cache", return_value=None)

    assert getmac.get_mac_address(**kwargs) is None


def test_ipconfig_exe_dns_suffix_that_looks_like_a_mac(mocker, get_sample):
    """
    The DNS suffix of a connection is set by the network (DHCP), and is printed before
    the MAC. One that looks like a MAC isn't returned as the MAC of the adapter.
    """
    sample = get_sample("windows_10/ipconfig-all.out")
    header = "Ethernet adapter Ethernet 3:\r\n\r\n   Connection-specific DNS Suffix  . :"
    assert sample.count(header) == 1
    crafted = sample.replace(header, header + " DE-AD-BE-EF-00-01", 1)
    method = getmac.IpconfigExe()

    mocker.patch("getmac.utils.popen", return_value=sample)
    by_name = method.get("Ethernet 3")
    by_description = method.get("Intel(R) Ethernet Connection I217-V")
    assert utils.clean_mac(by_name) not in (None, "de:ad:be:ef:00:01")
    assert by_description == by_name

    mocker.patch("getmac.utils.popen", return_value=crafted)
    assert method.get("Ethernet 3") == by_name
    assert method.get("Intel(R) Ethernet Connection I217-V") == by_name


def test_ipconfig_exe_mac_on_an_early_line_is_still_found(mocker):
    """If the only MAC in a section is on one of its first lines, it's used."""
    output = (
        "Windows IP Configuration\r\n\r\n"
        "Ethernet adapter Ethernet:\r\n\r\n"
        "   Description . . . . . . . . . . . : Some Adapter\r\n"
        "   Physical Address. . . . . . . . . : 00-11-22-33-44-55\r\n"
    )
    mocker.patch("getmac.utils.popen", return_value=output)

    assert getmac.IpconfigExe().get("Ethernet") == "00-11-22-33-44-55"


@pytest.mark.parametrize(
    ("iface", "output", "expected"),
    [
        # NetBSD prints the name of the Wi-Fi network before the address
        (
            "urtwn0",
            (
                "urtwn0: flags=0x8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
                '\tssid "x ether de:ad:be:ef:00:01" nwkey 65536\n'
                "\tpowersave off\n"
                "\tbssid 00:24:a5:af:dd:c0 chan 11\n"
                "\taddress: 00:0f:b5:11:22:33\n"
                "\tmedia: IEEE802.11 autoselect\n"
            ),
            "00:0f:b5:11:22:33",
        ),
        # FreeBSD prints the description before the address
        (
            "em0",
            (
                "em0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500\n"
                "\tdescription: connected to sw1 ether de:ad:be:ef:00:01\n"
                "\toptions=81009b<RXCSUM,TXCSUM,VLAN_MTU>\n"
                "\tether 00:a0:98:11:22:33\n"
            ),
            "00:a0:98:11:22:33",
        ),
        # No address of its own: the text isn't one
        (
            "tun0",
            (
                "tun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> metric 0 mtu 1500\n"
                "\tdescription: lladdr de:ad:be:ef:00:01 address: de:ad:be:ef:00:02\n"
                "\tinet 10.8.0.1 --> 10.8.0.2 netmask 0xffffffff\n"
            ),
            None,
        ),
    ],
)
def test_ifconfig_label_in_other_text_is_not_the_mac(iface, output, expected):
    assert getmac._parse_ifconfig(iface, output) == expected


def test_arp_does_not_look_up_names(mocker):
    """
    "arp <ip>" looks up the name of the host (a DNS request), which can take a long
    time, and the name can hide the entry. "-n" is used where the IP is an argument.
    """
    popen = mocker.patch("getmac.utils.popen", return_value="? (192.0.2.1) at 2:0:0:0:0:1 on en0")
    mocker.patch.object(consts, "DARWIN", True)

    getmac.ArpVariousArgs().get("192.0.2.1")
    getmac.ArpFreebsd().get("192.0.2.1")

    assert popen.call_args_list == [
        mocker.call("arp", "-n 192.0.2.1"),
        mocker.call("arp", "-n 192.0.2.1"),
    ]


@pytest.mark.parametrize("method_class", [getmac.ArpVariousArgs, getmac.ArpFreebsd])
def test_arp_longer_hardware_address_is_not_cut_to_a_mac(mocker, method_class):
    """An InfiniBand address is 20 bytes. Its first 6 aren't the MAC of the host."""
    infiniband = "80:00:02:08:fe:80:00:00:00:00:00:00:00:02:c9:03:00:1e:2f:11"
    mocker.patch.object(consts, "DARWIN", False)
    mocker.patch.object(consts, "SOLARIS", False)
    mocker.patch("getmac.utils.popen", return_value=f"? (192.0.2.1) at {infiniband} on ib0\n")

    assert method_class().get("192.0.2.1") is None

    mocker.patch("getmac.utils.popen", return_value="? (192.0.2.1) at 02:00:00:00:00:01 on em0\n")
    assert method_class().get("192.0.2.1") == "02:00:00:00:00:01"


def test_getmac_exe_output_that_cant_be_parsed(mocker):
    """A field longer than the csv module allows is not an error (which removes the method)."""
    mocker.patch("getmac.utils.popen", return_value='"Ethernet","' + "x" * 200000 + '"\r\n')

    assert getmac.GetmacExe().get("Ethernet") is None


def test_default_iface_netsh_long_metric(mocker):
    """A "metric" with thousands of digits is not a number int() can read."""
    route = "No       Manual    {}  0.0.0.0/0                  12  192.0.2.1\n"
    mocker.patch("getmac.utils.popen", return_value=route.format("9" * 5000))

    assert getmac.DefaultIfaceNetsh().get() is None


def test_default_interface_skips_addresses_that_are_not_macs(mocker):
    """A tunnel has a longer address. The search goes on to the next interface."""
    mocker.patch.object(consts, "WINDOWS", False)
    mocker.patch.object(gvars, "DEFAULT_IFACE", "nope0")
    mocker.patch("socket.if_nameindex", return_value=[(1, "lo"), (2, "ip6tnl0"), (3, "eth0")])
    macs = {"ip6tnl0": "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:01", "eth0": MAC}
    mocker.patch("getmac.getmac.get_by_method", side_effect=lambda _t, name, _n: macs.get(name))

    assert getmac.get_mac_address() == MAC


def test_read_file_that_cant_be_opened(mocker, tmp_path):
    (tmp_path / "file").write_text("data")
    mocker.patch("builtins.open", side_effect=PermissionError(13, "Permission denied"))

    assert utils.read_file(str(tmp_path / "file")) is None
