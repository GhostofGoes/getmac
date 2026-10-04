import os
import sys

import pytest

from getmac import utils
from getmac.variables import consts, gvars

MAC_RE_COLON = r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"


def test_check_path():
    assert utils.check_path(__file__)


def test_clean_mac():
    assert utils.clean_mac(None) is None
    assert utils.clean_mac("") is None
    assert utils.clean_mac(b"") is None
    assert utils.clean_mac("00:00:00:00:00:00:00:00:00") is None
    assert utils.clean_mac("00:0000:0000") is None
    assert utils.clean_mac("00000000000000000") is None
    assert utils.clean_mac("  00-50-56-C0-00-01  ") == "00:50:56:c0:00:01"
    assert utils.clean_mac("000000000000") == "00:00:00:00:00:00"
    assert utils.clean_mac("00:00:00:00:00:00") == "00:00:00:00:00:00"
    assert utils.clean_mac(b"00:00:00:00:00:00") == "00:00:00:00:00:00"


def test_read_file_return(mocker, get_sample):
    data = get_sample("ifconfig.out")
    mock_open = mocker.mock_open(read_data=data)
    mocker.patch("builtins.open", mock_open)
    assert utils.read_file("ifconfig.out") == data
    mock_open.assert_called_once_with("ifconfig.out")


def test_read_file_not_exist():
    assert utils.read_file("DOESNOTEXIST") is None


def test_search(get_sample):
    text = get_sample("ifconfig.out")
    regex = r"HWaddr " + MAC_RE_COLON
    assert utils.search(regex, "") is None
    assert utils.search(regex, text, 0) == "74:d4:35:e9:45:71"


def test_call_proc(mocker):
    mocker.patch("subprocess.DEVNULL", "DEVNULL")
    mocker.patch.object(gvars, "ENV", "ENV")

    mocker.patch.object(consts, "WINDOWS", True)
    m = mocker.patch("subprocess.check_output", return_value="WINSUCCESS")
    assert utils.call_proc("CMD", "arg") == "WINSUCCESS"
    m.assert_called_once_with("CMD arg", stderr="DEVNULL", env="ENV")

    mocker.patch.object(consts, "WINDOWS", False)
    m = mocker.patch("subprocess.check_output", return_value="YAY")
    assert utils.call_proc("CMD", "arg1 arg2") == "YAY"
    m.assert_called_once_with(["CMD", "arg1", "arg2"], stderr="DEVNULL", env="ENV")

    # check_output() returns bytes, since it isn't run in text mode
    mocker.patch("subprocess.check_output", return_value=b"BYTES")
    assert utils.call_proc("CMD", "arg") == "BYTES"


def test_call_proc_untrusted_arg(mocker):
    """The untrusted `arg` is passed as a single argument and is never split."""
    mocker.patch("subprocess.DEVNULL", "DEVNULL")
    mocker.patch.object(gvars, "ENV", "ENV")

    # POSIX: the trusted args are split, the untrusted arg is appended as one argument,
    # so it can't inject extra arguments even with spaces or a leading dash
    mocker.patch.object(consts, "WINDOWS", False)
    m = mocker.patch("subprocess.check_output", return_value="")
    utils.call_proc("CMD", "neighbor show", "10.0.0.1 -s evil")
    m.assert_called_once_with(
        ["CMD", "neighbor", "show", "10.0.0.1 -s evil"], stderr="DEVNULL", env="ENV"
    )

    # Windows: a single command-line string, with the untrusted arg quoted
    mocker.patch.object(consts, "WINDOWS", True)
    m = mocker.patch("subprocess.check_output", return_value="")
    utils.call_proc("CMD.exe", "-a", "10.0.0.1 -d *")
    m.assert_called_once_with('CMD.exe -a "10.0.0.1 -d *"', stderr="DEVNULL", env="ENV")


def test_call_proc_decode(mocker):
    mocker.patch.object(consts, "WINDOWS", False)
    mocker.patch("subprocess.check_output", return_value="Connexion au réseau local".encode())
    assert utils.call_proc("CMD", "arg") == "Connexion au réseau local"

    # Bytes that aren't UTF-8 are replaced, instead of failing the method
    mocker.patch("subprocess.check_output", return_value=b"Connexion au r\x82seau local")
    assert utils.call_proc("CMD", "arg") == "Connexion au r\ufffdseau local"


@pytest.mark.skipif(sys.platform != "win32", reason="The 'oem' codec only exists on Windows")
def test_call_proc_decode_windows_oem_code_page(mocker):
    """Windows commands print in the OEM code page, where 0x82 is "é" (cp437 and cp850)."""
    mocker.patch("subprocess.check_output", return_value=b"Connexion au r\x82seau local")
    assert utils.call_proc("ipconfig.exe", "/all") == "Connexion au réseau local"


def test_popen_path(mocker, tmp_path):
    """The command is run from the first PATH directory with an executable named after it."""
    is_dir = tmp_path / "is_dir"
    (is_dir / "testcmd").mkdir(parents=True)
    not_executable = tmp_path / "not_executable"
    not_executable.mkdir()
    (not_executable / "testcmd").write_text("")
    has_cmd = tmp_path / "has_cmd"
    has_cmd.mkdir()
    (has_cmd / "testcmd").write_text("")
    (has_cmd / "testcmd").chmod(0o755)

    path = [str(tmp_path / "missing"), str(is_dir), str(not_executable), str(has_cmd)]
    if sys.platform == "win32":
        # Windows doesn't have an executable permission, so any file would be used
        path.remove(str(not_executable))
    mocker.patch.object(gvars, "PATH", path)
    m = mocker.patch("getmac.utils.call_proc", return_value="SUCCESS")

    assert utils.popen("testcmd", "ARGS") == "SUCCESS"
    m.assert_called_once_with(str(has_cmd / "testcmd"), "ARGS", None)


def test_popen_not_found_raises(mocker, tmp_path):
    """popen() raises instead of running a bare command name not found in the PATH."""
    mocker.patch.object(gvars, "PATH", [str(tmp_path)])
    m = mocker.patch("getmac.utils.call_proc")
    with pytest.raises(FileNotFoundError, match="nonexistent"):
        utils.popen("nonexistent")
    m.assert_not_called()


def test_find_executable_skips_relative_dirs(mocker, tmp_path):
    """Relative PATH entries (including the current directory) are never searched."""
    (tmp_path / "testcmd").write_text("")
    (tmp_path / "testcmd").chmod(0o755)
    # A relative entry and an empty entry (which means the current directory)
    mocker.patch.object(gvars, "PATH", [".", "", "relative/dir"])
    assert utils.find_executable("testcmd") is None
    assert utils.check_command("testcmd") is False

    mocker.patch.object(gvars, "PATH", [str(tmp_path)])
    gvars.CHECK_COMMAND_CACHE.clear()
    assert utils.find_executable("testcmd") == str(tmp_path / "testcmd")


def test_find_executable_windows_extensions(mocker, tmp_path):
    """On Windows a command is found with a PATHEXT extension, e.g. "arp" -> "arp.exe"."""
    # The extension case matches PATHEXT, since this filesystem may be case-sensitive
    # (Windows, where this matters, isn't)
    (tmp_path / "cmd.EXE").write_text("")
    (tmp_path / "cmd.EXE").chmod(0o755)
    mocker.patch.object(consts, "WINDOWS", True)
    mocker.patch.dict(os.environ, {"PATHEXT": os.pathsep.join([".COM", ".EXE", ".BAT"])})
    mocker.patch.object(gvars, "PATH", [str(tmp_path)])

    assert utils.find_executable("cmd") == str(tmp_path / "cmd.EXE")
    # A name that already has the extension is found too
    assert utils.find_executable("cmd.EXE") == str(tmp_path / "cmd.EXE")
    assert utils.find_executable("missing") is None


def test_fetch_ip_using_dns(mocker):
    m = mocker.patch("socket.socket.__enter__")
    m.return_value.getsockname.return_value = ("1.2.3.4", 51327)
    assert utils.fetch_ip_using_dns() == "1.2.3.4"
