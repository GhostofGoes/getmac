# -*- coding: utf-8 -*-
import io
import os
import platform
import socket
from os import path

import pytest

import getmac

getmac.getmac.DEBUG = 4

TESTS_DIR = path.realpath(path.dirname(__file__))


@pytest.fixture()
def get_sample():
    def _get_sample(sample_path):
        sdir = path.join(TESTS_DIR, "samples")
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
def hermetic(mocker, tmp_path_factory):
    """
    Every test starts from the same state, whatever system it's run on, and can't
    use the system's network, commands or files by accident:

    - The platform is "linux" (tests of other platforms set the flags they need).
      ``native_platform`` puts the real flags back, for the few tests that need them.
    - The method caches are empty, and so is the ``PATH`` that commands are found
      with, so no command exists unless the test says so. The two methods that
      call the operating system directly (``CtypesHost`` on Windows, ``FcntlIface``
      on Linux) aren't available either.
    - Sockets are mocks (see ``mock_socket``), so no packet is sent.
    - Only files in the tests folder and pytest's temporary folder can be read
      with ``_read_file()``, and only they exist for ``check_path()``. Reading
      another file, or resolving a hostname, fails the test.
    """
    g = getmac.getmac
    violations = []

    for name, value in [
        ("WINDOWS", False),
        ("DARWIN", False),
        ("OPENBSD", False),
        ("FREEBSD", False),
        ("NETBSD", False),
        ("SOLARIS", False),
        ("BSD", False),
        ("WSL", False),
        ("LINUX", True),
        ("PLATFORM", "linux"),
        ("OVERRIDE_PLATFORM", ""),
        ("FORCE_METHOD", ""),
        ("DEFAULT_IFACE", ""),
        ("PATH", []),
        ("PATH_STR", ""),
        ("CHECK_COMMAND_CACHE", {}),
        ("METHOD_CACHE", dict.fromkeys(g.METHOD_CACHE)),
        ("FALLBACK_CACHE", dict((key, []) for key in g.FALLBACK_CACHE)),
        # The warning about old versions of Python is logged once per process
        ("WARNED_UNSUPPORTED_PYTHONS", True),
    ]:
        mocker.patch.object(g, name, value)

    # Otherwise CtypesHost would send a real ARP request on Windows, and the
    # methods that are used would depend on the system
    mocker.patch.object(g.CtypesHost, "test", return_value=False)
    mocker.patch.object(g.FcntlIface, "test", return_value=False)

    # socket.has_ipv6 is if Python was built with IPv6, which not all are
    mocker.patch("socket.has_ipv6", True)

    def _gethostbyname(hostname):
        violations.append("resolved the hostname %r" % (hostname,))
        raise socket.gaierror(-2, "Name or service not known (not resolved in tests)")

    mocker.patch("socket.gethostbyname", _gethostbyname)

    def _full_path(filepath):
        # The same text for the same file: links followed, and on Windows one case
        return path.normcase(path.realpath(str(filepath)))

    allowed = [
        _full_path(tmp_path_factory.getbasetemp()),
        _full_path(TESTS_DIR),
        _full_path(os.devnull),
    ]
    real_read_file = g._read_file
    real_check_path = g.check_path

    def _is_test_file(filepath):
        try:
            full = _full_path(filepath)
        except Exception:
            return False
        return any(full == root or full.startswith(root + os.sep) for root in allowed)

    def _read_file(filepath):
        if _is_test_file(filepath):
            return real_read_file(filepath)
        violations.append("read the file %r" % (filepath,))
        return None

    def _check_path(filepath):
        return _is_test_file(filepath) and real_check_path(filepath)

    mocker.patch.object(g, "_read_file", _read_file)
    mocker.patch.object(g, "check_path", _check_path)

    yield

    assert not violations, "The test used the real system: %s" % ", ".join(violations)


@pytest.fixture(autouse=True)
def mock_socket(mocker):
    """Don't send the UDP packet used to populate the ARP table onto the network."""
    return mocker.patch("socket.socket")


@pytest.fixture()
def native_platform(mocker):
    """The platform flags of the system the tests are run on, for tests of real commands."""
    g = getmac.getmac
    system = platform.system()
    bsd = system in ("OpenBSD", "FreeBSD", "NetBSD")
    for name, value in [
        ("WINDOWS", system == "Windows"),
        ("DARWIN", system == "Darwin"),
        ("OPENBSD", system == "OpenBSD"),
        ("FREEBSD", system == "FreeBSD"),
        ("NETBSD", system == "NetBSD"),
        ("SOLARIS", system == "SunOS"),
        ("BSD", bsd),
    ]:
        mocker.patch.object(g, name, value)
