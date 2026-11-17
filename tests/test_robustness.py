# -*- coding: utf-8 -*-

"""
Tests of how commands are run, and of files and command output that aren't valid
UTF-8.

NOTE: this file has to work on Python 2.7 too, like the rest of the 0.9.x tests.
"""

import logging
import os
import stat
import subprocess
import sys
import threading
from subprocess import CalledProcessError

import pytest

from getmac import getmac

MAC = "00:11:22:33:44:55"

EMPTY_CACHE = {"ip4": None, "ip6": None, "iface": None, "default_iface": None}


def _empty_fallback_cache():
    return {"ip4": [], "ip6": [], "iface": [], "default_iface": []}


# --- Files and the output of commands that aren't UTF-8 --------------------------

PROC_NET_ARP_BYTES = (
    b"IP address       HW type     Flags       HW address            Mask     Device\n"
    b"192.0.2.9        0x1         0x2         02:00:00:00:00:09     *        x\xff\xfe\n"
    b"192.0.2.1        0x1         0x2         02:00:00:00:00:01     *        eth0\n"
)


def test_read_file_bytes_that_are_not_utf8(mocker, tmpdir):
    """
    A name that isn't UTF-8 (Linux allows any bytes in an interface name) doesn't make
    the whole file unreadable, which would make the method fail and be removed.
    """
    arp = tmpdir.join("arp")
    arp.write_binary(PROC_NET_ARP_BYTES)

    data = getmac._read_file(str(arp))
    assert isinstance(data, str)
    assert "02:00:00:00:00:01" in data

    mocker.patch("getmac.getmac.ArpFile._path", str(arp))
    method = getmac.ArpFile()
    assert method.test() is True
    assert method.get("192.0.2.1") == "02:00:00:00:00:01"
    assert method.get("192.0.2.9") == "02:00:00:00:00:09"
    assert method.unusable is False

    # The whole lookup: ArpFile is still the method afterwards
    assert (
        getmac.get_mac_address(ip="192.0.2.1", network_request=False)
        == "02:00:00:00:00:01"
    )
    assert str(getmac.METHOD_CACHE["ip4"]) == "ArpFile"


def test_read_file_not_a_file(tmpdir):
    assert getmac._read_file(str(tmpdir)) is None
    assert getmac._read_file(str(tmpdir.join("missing"))) is None
    assert getmac._read_file(str(tmpdir.join("missing", "address"))) is None


def test_read_file_that_cant_be_opened(monkeypatch, tmpdir):
    tmpdir.join("file").write("data")
    builtins = "__builtin__" if sys.version_info[0] < 3 else "builtins"
    results = []
    for error in (IOError(13, "Permission denied"), OSError(5, "Input/output error")):

        def _open(*args, **kwargs):
            raise error

        # Only while the function is called: other code opens files too
        with monkeypatch.context() as patch:
            patch.setattr(builtins + ".open", _open)
            results.append(getmac._read_file(str(tmpdir.join("file"))))

    assert results == [None, None]
    assert getmac._read_file(str(tmpdir.join("file"))) == "data"


def test_command_output_that_is_not_utf8(mocker):
    """Bytes that aren't UTF-8 in the output of a command don't make a method fail."""
    output = (
        b"1: lo: <LOOPBACK,UP> mtu 65536\n    link/loopback 00:00:00:00:00:00\n"
        b"2: caf\xe9\xff: <BROADCAST,UP> mtu 1500\n    link/ether 02:00:00:00:00:09\n"
        b"3: eth0: <BROADCAST,UP> mtu 1500\n    link/ether 02:00:00:00:00:01\n"
    )
    mocker.patch("getmac.getmac.check_output", return_value=output)

    text = getmac._call_proc("/sbin/ip", "link")
    assert isinstance(text, str)
    assert "02:00:00:00:00:01" in text
    assert getmac.IpLinkIface().get("eth0") == "02:00:00:00:00:01"


def test_arping_error_output_that_is_not_utf8(mocker):
    """The same, for the output of "arping" when it fails."""
    failed = CalledProcessError(cmd="arping", returncode=1, output=b"\xff\xfe invalid")
    mocker.patch("getmac.getmac._popen", side_effect=failed)
    method = getmac.ArpingHost()

    assert method.get("192.0.2.1") is None

    # "invalid option" in the output means it's the other version of arping
    failed = CalledProcessError(
        cmd="arping", returncode=1, output=b"\xff arping: invalid option -- 'f'\n"
    )
    mocker.patch("getmac.getmac._popen", side_effect=[failed, MAC + "\n"])
    assert method.get("192.0.2.1") == MAC
    assert method._is_iputils is False


# --- Commands: time limit, and what they get from the program ---------------------


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
def test_command_timeout_setting(mocker, value, expected):
    """A timeout that can't be waited for means no timeout, and isn't an error."""
    mocker.patch("getmac.getmac.COMMAND_TIMEOUT", value)
    assert getmac._command_timeout() == expected

    check_output = mocker.patch("getmac.getmac.check_output", return_value=b"")
    getmac._call_proc("/sbin/cmd", "")
    assert check_output.call_args[1]["timeout"] == expected


def test_command_timeout_default():
    assert getmac.COMMAND_TIMEOUT == 15.0


def test_commands_get_no_input_and_errors_are_discarded(mocker):
    check_output = mocker.patch("getmac.getmac.check_output", return_value=b"")

    getmac._call_proc("/sbin/cmd", "")

    kwargs = check_output.call_args[1]
    assert sorted(kwargs) == ["env", "stderr", "stdin", "timeout"]
    assert kwargs["stdin"] is not None
    assert kwargs["stdin"] is kwargs["stderr"]
    assert kwargs["env"] is getmac.ENV


def test_null_device_is_open_for_reading():
    """
    Commands get the null device as their input, and for their errors. On Python 2,
    where there's no subprocess.DEVNULL, it's a file that's opened when getmac is
    imported, like before 0.9.7. It's open for reading as well now: a command that
    reads from a file that's only open for writing gets an error.
    """
    if sys.version_info[0] >= 3:
        assert getmac.DEVNULL == subprocess.DEVNULL
    else:
        assert getmac.DEVNULL.mode == "r+b"
        assert not getmac.DEVNULL.closed


@pytest.fixture
def null_device():
    """The null device as an open file, which is what DEVNULL is on Python 2."""
    null = open(os.devnull, "r+b")
    yield null
    null.close()


posix_only = pytest.mark.skipif(
    sys.platform == "win32",
    reason="Runs real commands, which isn't the same through a launcher on Windows",
)


def _fake_command(tmpdir, name, body):
    """A shell script in a new folder, and the PATH (a list) to find it with."""
    folder = tmpdir.mkdir("bin-" + name)
    command = folder.join(name)
    command.write("#!/bin/sh\n" + body + "\n")
    command.chmod(command.stat().mode | stat.S_IXUSR)
    return [str(folder)]


@posix_only
@pytest.mark.parametrize("use_python2_function", [True, False])
def test_real_command_output_exit_code_and_input(
    mocker, tmpdir, capfd, null_device, use_python2_function
):
    """
    Real commands, with the function that's used on this version of Python, and
    with the one for Python 2 (which works on every version).
    """
    if use_python2_function:
        mocker.patch("getmac.getmac.check_output", getmac._check_output_py2)
        mocker.patch("getmac.getmac.DEVNULL", null_device)
    path = _fake_command(
        tmpdir,
        "fakearp",
        'echo "errors" >&2\n'
        'if [ "$1" = "fail" ]; then echo "some output"; exit 3; fi\n'
        'echo "input=[$(cat)] args=[$*]"',
    )
    mocker.patch("getmac.getmac.PATH", path)

    # The output is returned, the command has no input, and its errors are discarded
    assert getmac._popen("fakearp", "-a -n x y") == "input=[] args=[-a -n x y]\n"

    # An exit code that isn't zero is an error, with the output and the exit code
    with pytest.raises(CalledProcessError) as excinfo:
        getmac._popen("fakearp", "fail")
    assert excinfo.value.returncode == 3
    assert excinfo.value.output == b"some output\n"

    out, err = capfd.readouterr()
    assert "errors" not in out + err


@posix_only
@pytest.mark.parametrize("use_python2_function", [True, False])
def test_real_command_is_stopped_after_the_timeout(
    mocker, tmpdir, null_device, use_python2_function
):
    """A command that doesn't finish is stopped, and it's an error for the method."""
    if use_python2_function:
        mocker.patch("getmac.getmac.check_output", getmac._check_output_py2)
        mocker.patch("getmac.getmac.DEVNULL", null_device)
    proof = tmpdir.join("proof")
    path = _fake_command(
        tmpdir,
        "fakearp",
        "echo started > '%s'\nexec sleep 60\necho finished >> '%s'" % (proof, proof),
    )
    mocker.patch("getmac.getmac.PATH", path)
    mocker.patch("getmac.getmac.COMMAND_TIMEOUT", 0.5)
    done = []

    def _run():
        try:
            getmac._popen("fakearp", "-n 192.0.2.1")
        except Exception as ex:
            done.append(ex)
        else:
            done.append(None)

    # In a thread, so the test fails if the command isn't stopped, and doesn't hang
    thread = threading.Thread(target=_run)
    thread.daemon = True
    thread.start()
    thread.join(30)

    assert done, "The command wasn't stopped"
    assert isinstance(done[0], getmac.TimeoutExpired)
    assert done[0].timeout == 0.5
    assert "fakearp" in str(done[0])
    assert proof.read() == "started\n"


@posix_only
@pytest.mark.parametrize("use_python2_function", [True, False])
def test_real_command_without_a_timeout(
    mocker, tmpdir, null_device, use_python2_function
):
    """COMMAND_TIMEOUT = 0 or None is no time limit, like before 0.9.7."""
    if use_python2_function:
        mocker.patch("getmac.getmac.check_output", getmac._check_output_py2)
        mocker.patch("getmac.getmac.DEVNULL", null_device)
    mocker.patch("getmac.getmac.PATH", _fake_command(tmpdir, "fakearp", "echo ok"))

    for timeout in (0, None):
        mocker.patch("getmac.getmac.COMMAND_TIMEOUT", timeout)
        assert getmac._popen("fakearp", "") == "ok\n"


@posix_only
@pytest.mark.parametrize("use_python2_function", [True, False])
def test_real_command_does_not_get_open_files(
    mocker, tmpdir, null_device, use_python2_function
):
    """
    A command isn't given the files and sockets the program has open. Python 2
    passes all of them on unless it's told not to.
    """
    if use_python2_function:
        mocker.patch("getmac.getmac.check_output", getmac._check_output_py2)
        mocker.patch("getmac.getmac.DEVNULL", null_device)
    path = _fake_command(
        tmpdir,
        "fakearp",
        'for fd in "$@"; do if [ -e "/dev/fd/$fd" ]; then echo "open: $fd"; fi; done\n'
        "echo checked",
    )
    mocker.patch("getmac.getmac.PATH", path)
    import fcntl

    secret = open(str(tmpdir.join("secret-key.pem")), "w+")
    read_end, write_end = os.pipe()
    fds = []
    try:
        for fd in (secret.fileno(), read_end, write_end):
            # Copies with high numbers, which a command gets if it's given every
            # file (they're inheritable). The shell that runs the command uses some
            # low numbers itself, e.g. 10 for its script.
            fds.append(fcntl.fcntl(fd, fcntl.F_DUPFD, 200))
        output = getmac._popen("fakearp", " ".join(str(fd) for fd in fds))
    finally:
        secret.close()
        for fd in [read_end, write_end] + fds:
            os.close(fd)

    assert output == "checked\n"


def test_timeout_is_an_error_for_the_method(mocker, caplog):
    """
    A command that's stopped is like any other error in a method: the method isn't
    used again, and the next one is tried. (It's the same in getmac 1.0.0.)
    """
    timeout = getmac.TimeoutExpired(["/sbin/ip", "neighbor", "show"], 15.0)
    assert "timed out" in str(timeout)
    slow = getmac.IpNeighborShow()
    mocker.patch.object(slow, "get", side_effect=timeout)
    other = getmac.ArpVariousArgs()
    mocker.patch.object(other, "get", return_value=MAC)
    cache = dict(EMPTY_CACHE)
    cache["ip4"] = slow
    fallback = _empty_fallback_cache()
    fallback["ip4"] = [other]
    mocker.patch("getmac.getmac.METHOD_CACHE", cache)
    mocker.patch("getmac.getmac.FALLBACK_CACHE", fallback)
    caplog.set_level(logging.WARNING, logger="getmac")

    assert getmac.get_mac_address(ip="192.0.2.1", network_request=False) == MAC

    assert slow.unusable is True
    assert getmac.METHOD_CACHE["ip4"] is other
    assert "timed out" in caplog.text


def test_timeout_reaches_the_method_from_a_command(mocker):
    """The exception isn't hidden by the methods that try more than one command."""
    timeout = getmac.TimeoutExpired(["/sbin/arp", "-n", "192.0.2.1"], 15.0)
    mocker.patch("getmac.getmac._popen", side_effect=timeout)

    for method_class in (getmac.ArpVariousArgs, getmac.IfconfigOther):
        with pytest.raises(getmac.TimeoutExpired):
            method_class().get("192.0.2.1")
    for method_class in (
        getmac.ArpFreebsd,
        getmac.ArpExe,
        getmac.IpNeighborShow,
        getmac.DarwinNetworksetupIface,
        getmac.IfconfigWithIfaceArg,
        getmac.IfconfigEther,
        getmac.IpLinkIface,
    ):
        with pytest.raises(getmac.TimeoutExpired):
            method_class().get("192.0.2.1")
