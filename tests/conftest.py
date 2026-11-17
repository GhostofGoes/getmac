# -*- coding: utf-8 -*-
import io
from os import path

import pytest

import getmac

getmac.getmac.DEBUG = 4


@pytest.fixture()
def get_sample():
    def _get_sample(sample_path):
        sdir = path.realpath(path.join(path.dirname(__file__), "samples"))
        with io.open(
            path.join(sdir, sample_path), "rt", newline="", encoding="utf-8"
        ) as f:
            return f.read()

    return _get_sample


try:
    import pytest_benchmark  # noqa: F401
except ImportError:
    # pytest-benchmark isn't needed to run the tests (it isn't in
    # test-requirements.txt). Without it, "benchmark" just calls the function.
    @pytest.fixture()
    def benchmark():
        def _benchmark(func, *args, **kwargs):
            return func(*args, **kwargs)

        return _benchmark


@pytest.fixture(autouse=True)
def mock_socket(mocker):
    """
    Sockets are mocks in every test, so no packet is sent onto the network, and
    the tests pass on a system without IPv6.
    """
    return mocker.patch("socket.socket")


@pytest.fixture(autouse=True)
def no_system_arp_table(mocker, tmpdir):
    """
    The ARP table of the system the tests are run on isn't read, so the
    results don't depend on what's in it.
    """
    mocker.patch("getmac.getmac.ArpFile._path", str(tmpdir.join("no_arp_table")))
