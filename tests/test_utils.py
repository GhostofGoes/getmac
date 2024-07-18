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
    mocker.patch("getmac.utils.DEVNULL", "DEVNULL")
    mocker.patch.object(gvars, "ENV", "ENV")

    mocker.patch.object(consts, "WINDOWS", True)
    m = mocker.patch("getmac.utils.check_output", return_value="WINSUCCESS")
    assert utils.call_proc("CMD", "arg") == "WINSUCCESS"
    m.assert_called_once_with("CMD arg", stderr="DEVNULL", env="ENV")

    mocker.patch.object(consts, "WINDOWS", False)
    m = mocker.patch("getmac.utils.check_output", return_value="YAY")
    assert utils.call_proc("CMD", "arg1 arg2") == "YAY"
    m.assert_called_once_with(["CMD", "arg1", "arg2"], stderr="DEVNULL", env="ENV")


def test_uuid_convert():
    assert utils.uuid_convert(2482700837424) == "02:42:0C:80:62:30"
    assert utils.uuid_convert(278094213753144) == "FC:EC:DA:D3:29:38"


def test_fetch_ip_using_dns(mocker):
    m = mocker.patch("socket.socket.__enter__")
    m.return_value.getsockname.return_value = ("1.2.3.4", 51327)
    assert utils.fetch_ip_using_dns() == "1.2.3.4"
