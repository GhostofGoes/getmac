import importlib.util
import os
import platform

import pytest

import getmac.variables
from getmac.getmac import Method
from getmac.variables import Constants, Variables


def _load_constants(mocker, system, release, version):
    """
    Detect the platform as if ``platform.uname()`` returned the given values. Platform
    detection runs when getmac/variables.py is imported, so this imports a separate copy of
    it and returns that copy's Constants class. The getmac.variables module is left alone.
    """
    uname = platform.uname_result(system, "hostname", release, version, "x86_64")
    mocker.patch("platform.uname", return_value=uname)
    spec = importlib.util.spec_from_file_location(
        "_getmac_variables_copy", getmac.variables.__file__
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Constants


@pytest.mark.parametrize(
    ("uname", "wsl1", "wsl2", "linux", "expected_platform"),
    [
        # WSL1 has "Microsoft" in the kernel release and version, and is the "wsl" platform
        (
            ("Linux", "4.4.0-17763-Microsoft", "#253-Microsoft Mon Dec 31 17:49:00 PST 2018"),
            True,
            False,
            False,
            "wsl",
        ),
        (
            ("Linux", "4.4.0-19041-Microsoft", "#1237-Microsoft Sat Sep 11 14:32:00 PST 2021"),
            True,
            False,
            False,
            "wsl",
        ),
        # WSL2 is a Linux VM, so it's the "linux" platform
        (
            ("Linux", "5.15.90.1-microsoft-standard-WSL2", "#1 SMP Fri Jan 27 02:56:13 UTC 2023"),
            False,
            True,
            True,
            "linux",
        ),
        # Older WSL2 kernels don't have "-WSL2" at the end of the release
        (
            ("Linux", "4.19.128-microsoft-standard", "#1 SMP Tue Jun 23 12:58:10 UTC 2020"),
            False,
            True,
            True,
            "linux",
        ),
        (
            ("Linux", "6.8.0-45-generic", "#45-Ubuntu SMP PREEMPT_DYNAMIC Fri Aug 30 2024"),
            False,
            False,
            True,
            "linux",
        ),
        # Other platforms are the lowercase result of platform.system()
        (("Windows", "10", "10.0.19045"), False, False, False, "windows"),
        (("Darwin", "23.1.0", "Darwin Kernel Version 23.1.0"), False, False, False, "darwin"),
        (("FreeBSD", "11.2-RELEASE", "FreeBSD 11.2-RELEASE"), False, False, False, "freebsd"),
        (("OpenBSD", "6.4", "GENERIC#349"), False, False, False, "openbsd"),
        (("SunOS", "5.10", "Generic_147148-26"), False, False, False, "sunos"),
        (("HP-UX", "B.11.31", "U"), False, False, False, "hp-ux"),
    ],
)
def test_constants_platform_detection(mocker, uname, wsl1, wsl2, linux, expected_platform):
    constants = _load_constants(mocker, *uname)

    assert constants.WSL1 is wsl1
    assert constants.WSL2 is wsl2
    assert constants.LINUX is linux
    assert constants.PLATFORM == expected_platform
    # Detected platforms must match the names methods use in their "platforms"
    assert constants.PLATFORM in Method.VALID_PLATFORM_NAMES


def test_load_constants_leaves_getmac_variables_alone(mocker):
    """Sanity check for _load_constants(), since other tests use getmac.variables."""
    real_platform = getmac.variables.consts.PLATFORM

    _load_constants(mocker, "Linux", "4.4.0-17763-Microsoft", "#253-Microsoft")

    assert getmac.variables.consts.PLATFORM == real_platform
    assert getmac.variables.Constants is Constants


@pytest.mark.parametrize(
    ("windows", "path", "expected"),
    [
        # Python "Scripts" folders are removed on Windows, so getmac's own "getmac.exe"
        # script (or a pip-installed "ping.exe") isn't run instead of the Windows command
        (
            True,
            [
                "C:\\Windows\\system32",
                "C:\\Users\\user\\AppData\\Local\\Programs\\Python\\Python313\\Scripts",
                "C:\\Users\\user\\AppData\\Local\\Programs\\Python\\Python313",
                "C:\\Users\\user\\getmac\\Scripts",
                "C:\\Windows",
            ],
            [
                "C:\\Windows\\system32",
                "C:\\Users\\user\\AppData\\Local\\Programs\\Python\\Python313",
                "C:\\Windows",
            ],
        ),
        # sbin folders are added on other platforms, a lot of the commands are in them
        (
            False,
            ["/usr/local/bin", "/usr/bin"],
            ["/usr/local/bin", "/usr/bin", "/sbin", "/usr/sbin"],
        ),
    ],
)
def test_variables_path(mocker, windows, path, expected):
    mocker.patch.object(Constants, "WINDOWS", windows)
    # Variables() changes these class attributes in place, so use copies
    mocker.patch.object(Variables, "PATH", list(path))
    mocker.patch.object(Variables, "ENV", {"PATH": os.pathsep.join(path)})

    variables = Variables()

    assert variables.PATH == expected
    assert variables.PATH_STR == os.pathsep.join(expected)
    # Command output is parsed in English
    assert variables.ENV["LC_ALL"] == "C"
