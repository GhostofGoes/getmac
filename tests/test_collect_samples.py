"""Tests for scripts/collect_samples.py, the script that collects samples for these tests."""

import importlib.util
import inspect
import platform
import shlex
from contextlib import suppress
from pathlib import Path
from subprocess import CalledProcessError

import pytest

from getmac import getmac

SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "collect_samples.py"


@pytest.fixture(scope="module")
def collect_samples():
    if not SCRIPT_PATH.exists():  # The scripts aren't in the sdist, but the tests are
        pytest.skip(f"{SCRIPT_PATH} not found")
    spec = importlib.util.spec_from_file_location("collect_samples", SCRIPT_PATH)
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _method_classes():
    """Every Method subclass in getmac/getmac.py, including ones that aren't in METHODS."""
    classes = []
    to_check = [getmac.Method]
    while to_check:
        for subclass in to_check.pop().__subclasses__():
            to_check.append(subclass)
            if subclass.__module__ == getmac.__name__:
                classes.append(subclass)
    return classes


def _fake_popen(commands, result):
    def popen(command, args):
        commands.add((command, *shlex.split(args)))
        if isinstance(result, Exception):
            raise result
        return result

    return popen


def _record_method(mocker, method_class):
    """
    Run a Method with fake commands that fail in different ways, so its fallbacks get used,
    and record the commands it checks for and runs, and the files it reads. Interface and IP
    arguments are recorded as "{iface}" and "{ip}", the placeholders used by the script.
    """
    if method_class.method_type == "iface":
        arg = "{iface}"
    elif method_class.method_type in ("ip", "ip4", "ip6"):
        arg = "{ip}"
    else:
        arg = ""

    checked, commands, files = set(), set(), set()
    mocker.patch("getmac.utils.check_command", side_effect=lambda c: checked.add(c) or True)
    mocker.patch("getmac.utils.read_file", side_effect=lambda path: files.add(path))
    mocker.patch("getmac.getmac.socket.gethostbyname", side_effect=OSError)  # CtypesHost
    with suppress(Exception):
        method_class().test()

    for result in (
        "",
        # Methods like ArpingHost and IfconfigOther try other arguments on errors
        CalledProcessError(1, "cmd", output=b"invalid option"),
        # IpLinkIface uses "ip link" when "ip link show <iface>" exits with 255
        CalledProcessError(255, "cmd", output=b""),
    ):
        mocker.patch("getmac.utils.popen", side_effect=_fake_popen(commands, result))
        with suppress(Exception):  # Methods failing doesn't matter, only what they run
            method_class().get(arg)

    return checked, commands, files


@pytest.mark.parametrize("method_class", _method_classes(), ids=lambda m: m.__name__)
def test_collects_everything_methods_use(mocker, collect_samples, method_class):
    """
    Fails if a Method uses a command or file that isn't collected by
    scripts/collect_samples.py for all of the Method's platforms.
    """
    checked, commands, files = _record_method(mocker, method_class)

    # Make sure the recording worked, so this can't pass by accident
    source = inspect.getsource(method_class)
    assert bool(commands) == ("utils.popen(" in source)
    assert bool(files) == ("utils.read_file(" in source)

    assert method_class.platforms
    for platform_name in method_class.platforms:
        assert platform_name in collect_samples.PLATFORMS, (
            f"add platform '{platform_name}' to PLATFORMS in scripts/collect_samples.py"
        )

        specs = collect_samples.specs_for_platform(platform_name)
        script_commands = {s.argv for s in specs if isinstance(s, collect_samples.Command)}
        script_files = {s.path for s in specs if isinstance(s, collect_samples.File)}

        missing = (
            (commands - script_commands)
            | (files - script_files)
            | (checked - {argv[0] for argv in script_commands})
        )
        assert not missing, (
            f"add {sorted(map(str, missing))} to GROUPS in scripts/collect_samples.py "
            f"for platform '{platform_name}'"
        )


@pytest.mark.parametrize(
    ("argv", "strip_exe", "expected"),
    [
        # Names of existing samples
        (("ip", "route", "list", "0/0"), False, "ip_route_list_0slash0.out"),
        (("arp", "-a"), False, "arp_-a.out"),
        (("ifconfig", "eth8"), False, "ifconfig_eth8.out"),
        (("arp", "10.0.2.2"), False, "arp_10-0-2-2.out"),
        (("ip", "neighbor", "show", "192.168.16.2"), False, "ip_neighbor_show_192-168-16-2.out"),
        (
            ("busybox", "arping", "-f", "-c", "1", "172.29.16.1"),
            False,
            "busybox_arping_-f_-c_1_172-29-16-1.out",
        ),
        (("route", "-n", "get", "default"), False, "route_-n_get_default.out"),
        (("netsh.exe", "int", "ipv4", "show", "neigh"), True, "netsh_int_ipv4_show_neigh.out"),
        (("route.exe", "print", "-4"), True, "route_print_-4.out"),
        # Windows options, IPv6 addresses, and Windows commands run from WSL
        (("ipconfig.exe", "/all"), True, "ipconfig_-all.out"),
        (("ip", "neighbor", "show", "fe80::1"), False, "ip_neighbor_show_fe80--1.out"),
        (("arp.exe", "-a"), False, "arp.exe_-a.out"),
    ],
)
def test_sample_filename(collect_samples, argv, strip_exe, expected):
    assert collect_samples.sample_filename(argv, strip_exe) == expected


@pytest.mark.parametrize(
    ("sample_file", "interfaces", "expected"),
    [
        ("ubuntu_18.04/ip_route_list_0slash0.out", [], ("ens33", "192.168.16.2")),
        ("ubuntu_18.04/route_-n.out", ["lo", "ens33"], ("ens33", "192.168.16.2")),
        ("freebsd11/route_get_default.out", [], ("em0", "10.0.2.2")),
        ("macos_10.12.6/netstat_-rn.out", ["lo0", "en0"], ("en0", "10.0.2.2")),
        ("third_party/glpi_agent/hpux/netstat/hpux1", ["lo0", "lan0"], ("lan0", "10.0.4.33")),
    ],
)
def test_parse_default_route(collect_samples, get_sample, sample_file, interfaces, expected):
    assert collect_samples.parse_default_route(get_sample(sample_file), interfaces) == expected


def test_parse_ipconfig_and_proc_net_route(collect_samples, get_sample):
    adapters, iface, gateway = collect_samples.parse_ipconfig(
        get_sample("windows_10/ipconfig-all.out")
    )
    assert adapters == ["Ethernet 3", "VMnet1", "VMnet8", "Local Area Connection* 1"]
    assert (iface, gateway) == ("Ethernet 3", "10.0.0.1")

    data = get_sample("ubuntu_18.10/proc_net_route.out")
    assert collect_samples.parse_proc_net_route(data) == ("ens33", "192.168.16.2")


def test_file_sample_filename(collect_samples):
    assert collect_samples.file_sample_filename("/proc/net/arp") == "cat_proc-net-arp.out"
    assert (
        collect_samples.file_sample_filename("/sys/class/net/eth0/address")
        == "cat_sys-class-net-eth0-address.out"
    )


@pytest.mark.parametrize(
    ("uname", "os_release", "expected"),
    [
        (
            ("Linux", "4.15.0-20-generic", "#21-Ubuntu SMP"),
            {"ID": "ubuntu", "VERSION_ID": "18.04"},
            "ubuntu_18.04",
        ),
        (
            ("Linux", "4.4.0-17763-Microsoft", "#253-Microsoft"),
            {"ID": "ubuntu", "VERSION_ID": "18.04"},
            "WSL_ubuntu_18.04",
        ),
        (
            ("Linux", "5.15.90.1-microsoft-standard-WSL2", "#1 SMP"),
            {"ID": "kali", "VERSION_ID": "2023.1"},
            "WSL2_kali_2023.1",
        ),
        (("Linux", "6.9.7-arch1-1", "#1 SMP"), {"ID": "arch"}, "arch"),
        (("Linux", "6.1.0", "#1 SMP"), {}, "linux_6.1.0"),
        (("Darwin", "16.7.0", "Darwin Kernel Version 16.7.0"), {}, "macos_10.12.6"),
        (("Windows", "10", "10.0.19045"), {}, "windows_10"),
        (("Windows", "10", "10.0.22631"), {}, "windows_11"),
        (("FreeBSD", "11.2-RELEASE", "FreeBSD 11.2-RELEASE"), {}, "freebsd_11.2"),
        (("OpenBSD", "6.4", "GENERIC#349"), {}, "openbsd_6.4"),
        (("SunOS", "5.10", "Generic_147148-26"), {}, "solaris_10"),
        (("HP-UX", "B.11.31", "U"), {}, "hpux_11.31"),
        (("AIX", "2", "7"), {}, "aix_7.2"),
    ],
)
def test_default_dir_name(mocker, collect_samples, uname, os_release, expected):
    mocker.patch.object(collect_samples, "is_android", return_value=False)
    mocker.patch("platform.mac_ver", return_value=("10.12.6", ("", "", ""), "x86_64"))
    system, release, version = uname
    uname = platform.uname_result(system, "hostname", release, version, "x86_64")
    assert collect_samples.default_dir_name(uname, os_release) == expected


def test_main(mocker, capsys, tmp_path, collect_samples):
    """Collect samples with fake commands, without running anything for real."""

    def fake_run_command(argv, *_args):
        if argv[0] == "/bin/ndp":
            return collect_samples.RunResult(1, b"some output\n", b"ndp: error!")
        if argv[0] == "/bin/arping":
            return collect_samples.RunResult(None, b"", b"", "timed out after 15.0s")
        return collect_samples.RunResult(0, " ".join(argv).encode() + b"\r\n", b"")

    mocker.patch.object(
        collect_samples,
        "find_command",
        side_effect=lambda command, _: None if command == "ifconfig" else f"/bin/{command}",
    )
    mocker.patch.object(collect_samples, "run_command", side_effect=fake_run_command)
    mocker.patch.object(collect_samples, "find_interfaces", return_value=["lo0", "en0"])
    mocker.patch.object(collect_samples, "find_default_route", return_value=("en0", "10.0.0.1"))
    args = ["--platform", "darwin", "--output-root", str(tmp_path), "--name", "macos"]
    out_dir = tmp_path / "macos"

    assert collect_samples.main([*args, "--dry-run"]) == 0
    assert "would run  route -n get default -> route_-n_get_default.out" in capsys.readouterr().out
    assert not out_dir.exists()

    assert collect_samples.main([*args, "--default-interface-only"]) == 0
    output = capsys.readouterr().out
    # Output is saved as-is, including Windows line endings
    assert (out_dir / "route_-n_get_default.out").read_bytes() == b"/bin/route -n get default\r\n"
    assert (out_dir / "arp_-a_10-0-0-1.out").exists()
    assert (out_dir / "networksetup_-getmacaddress_en0.out").exists()
    assert not (out_dir / "networksetup_-getmacaddress_lo0.out").exists()
    assert "Not installed, skipping: ifconfig" in output
    assert not list(out_dir.glob("ifconfig*"))
    # Failures are recorded and don't stop the other commands
    assert (out_dir / "ndp_-an.out").read_bytes() == b"some output\n"
    assert "ndp -an  (exit code 1, output saved)" in output
    assert "arping -f -c 1 10.0.0.1  (timed out after 15.0s)" in output
    assert not list(out_dir.glob("arping*"))
    assert (
        "[failed] ndp -an (exit code 1, output saved)\n    stderr: ndp: error!"
        in (out_dir / "collect_samples.log").read_text()
    )
    assert "real MAC addresses, IP addresses, and hostnames" in output

    # Existing samples are only overwritten with --force
    (out_dir / "sw_vers.out").write_bytes(b"old")
    collect_samples.main(args)
    assert "exists  sw_vers -> sw_vers.out" in capsys.readouterr().out
    assert (out_dir / "sw_vers.out").read_bytes() == b"old"
    collect_samples.main([*args, "--force"])
    assert (out_dir / "sw_vers.out").read_bytes() == b"/bin/sw_vers\r\n"
