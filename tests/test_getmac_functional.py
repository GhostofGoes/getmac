
from io import open
from os import path

import pytest

import getmac
getmac.getmac.DEBUG = True


@pytest.fixture
def get_sample():
    def _get_sample(sample_path):
        sdir = path.realpath(path.join(path.dirname(__file__), '..', 'samples'))
        with open(path.join(sdir, sample_path), 'rt', newline='', encoding='utf-8') as f:
            return f.read()
    return _get_sample


def test_linux_ifconfig(mocker, get_sample):
    # content = get_sample('ifconfig.out')
    getmac.getmac.WINDOWS = False
    getmac.getmac.OSX = False
    getmac.getmac.WSL = False
    getmac.getmac.LINUX = True
    # mocker.patch

    assert '74:d4:35:e9:45:71' == getmac.get_mac_address(interface='eth0')


def test_linux_ip_link(mocker, get_sample):
    # content = get_sample('ip_link_list.out')
    assert '74:d4:35:e9:45:71' == getmac.get_mac_address(interface='eth0')


def test_osx_ifconfig(mocker, get_sample):
    # content = get_sample(path.join('OSX', 'ifconfig.out'))
    pass
