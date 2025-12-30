"""
Global variables, constants, and settings for the getmac package.
"""

import logging
import os
import platform
import sys
from typing import Dict, Final, List


class VarsClass:
    pass


class Settings(VarsClass):
    """
    User-configurable settings.
    """

    DEBUG: int = 0
    """
    Debugging level. Increased value => more output. 4 is roughly the highest.
    """

    PORT: int = 55555
    """
    UDP port to use for populating the ARP table (IPv4) or NDP list (IPv6)
    when looking up MACs for hosts or IPs.
    """

    # TODO: This will change to a function argument in 1.0.0
    OVERRIDE_PLATFORM: str = ""
    """
    User-configurable override to force a specific platform.
    """

    FORCE_METHOD: str = ""
    """
    Force a specific method to be used for all lookups.
    Used for debugging and testing.
    """


class Constants(VarsClass):
    """
    Platform identifiers and other constants.
    """

    _UNAME: Final[platform.uname_result] = platform.uname()
    _SYST: Final[str] = _UNAME.system

    WINDOWS: Final[bool] = _SYST == "Windows"
    DARWIN: Final[bool] = _SYST == "Darwin"
    OPENBSD: Final[bool] = _SYST == "OpenBSD"
    FREEBSD: Final[bool] = _SYST == "FreeBSD"
    NETBSD: Final[bool] = _SYST == "NetBSD"
    SOLARIS: Final[bool] = _SYST == "SunOS"
    HPUX: Final[bool] = _SYST == "HP-UX"

    BSD: Final[bool] = OPENBSD or FREEBSD or NETBSD
    """
    .. note::
       This doesn't include Darwin or Solaris as a "BSD".

    :meta hide-value:
    """

    WSL1: Final[bool] = (
        _SYST == "Linux"
        and "Microsoft" in _UNAME.version
        and "-WSL2" not in _UNAME.release
    )
    """
    Windows Subsystem for Linux (WSL) version 1.
    The version that's a very cool abstraction layer
    remapping Linux syscalls to Windows syscalls.

    :meta hide-value:
    """

    WSL2: Final[bool] = (
        _SYST == "Linux"
        and "Microsoft" not in _UNAME.version
        and "-WSL2" in _UNAME.release
    )
    """
    Windows Subsystem for Linux (WSL) version 2.
    The version that's basically a fancy Linux VM on Hyper-V.

    :meta hide-value:
    """

    LINUX: Final[bool] = _SYST == "Linux" and not WSL1
    """
    If the system is running Linux (excluding WSL1).

    :meta hide-value:
    """

    ANDROID: Final[bool] = (
        hasattr(sys, "getandroidapilevel") or "ANDROID_STORAGE" in os.environ
    )
    """
    .. note::
       "Linux" methods apply to Android without modifications.
       If there's Android-specific stuff then we can add a platform
       identifier for it.

    :meta hide-value:
    """

    PLATFORM: Final[str] = "wsl" if (LINUX and WSL1) else _SYST.lower()
    """
    Generic platform identifier used for filtering methods.

    # TODO: change "wsl" to "wsl1", since WSL2 method should just work like normal linux

    Possible values:

    - wsl
    - linux
    - windows
    - darwin
    - openbsd
    - freebsd
    - netbsd
    - sunos
    - hp-ux
    - Any other values that can be returned by :func:`platform.uname`,
        converted to lowercase.

    :meta hide-value:
    """

    MAC_RE_COLON: Final[str] = r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"
    """
    Regular expression pattern for MAC addresses with ``:`` (colon) characters.
    """

    MAC_RE_DASH: Final[str] = r"([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})"
    """
    Regular expression pattern for MAC addresses with ``-`` (dash) characters.
    """

    MAC_RE_SHORT: Final[str] = r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})"
    """
    On OSX, some MACs in ``arp`` output may have a single digit instead of two.
    This can also happen on other platforms, like Solaris.

    Examples:

    - ``18:4f:32:5a:64:5``  (note the ``:5`` at the end)
    - ``14:cc:20:1a:99:0`` (note the ``:0`` at the end)
    """


class Variables(VarsClass):
    """
    Things that can change.

    Essentially most of the global variables in getmac.
    """

    PATH: List[str] = os.environ.get("PATH", os.defpath).split(os.pathsep)
    """
    Get and cache the configured system PATH environment variable on import.
    The process environment does not change after a process is started.

    :meta hide-value:
    """

    PATH_STR: str = os.pathsep.join(PATH)
    """
    The :attr:`~getmac.variables.Variables.PATH` as a string.
    Used for lookups by :func:`getmac.utils.check_command`,
    which uses :func:`shutil.which` under the hood.

    :meta hide-value:
    """

    ENV: Dict[str, str] = dict(os.environ)
    """
    Use a copy of the environment so any modifications that need to be made
    for operation of getmac doesn't modify the process's current environment.

    :meta hide-value:
    """

    CHECK_COMMAND_CACHE: Dict[str, bool] = {}
    """
    Cache of commands that have been checked for existence by
    :func:`~getmac.utils.check_command`. This speeds up subsequent
    lookups of the same command. The key is the command name, and
    the value is a boolean indicating if it exists.
    """

    log: logging.Logger = logging.getLogger("getmac")
    """
    Global logger for getmac. The logger name is `getmac`.

    :meta hide-value:
    """

    DEFAULT_IFACE: str = ""
    """
    Name of the local host's default network interface.
    """

    def __init__(self) -> None:
        super().__init__()

        if not self.log.handlers:
            self.log.addHandler(logging.NullHandler())

        self.ENV["LC_ALL"] = "C"  # Ensure ASCII output so we parse correctly

        if not Constants.WINDOWS:
            self.PATH.extend(("/sbin", "/usr/sbin"))
        else:
            # Prevent edge case on Windows where our script "getmac.exe"
            # gets added to the path ahead of the actual Windows getmac.exe.
            # This also prevents Python Scripts folders from being added, e.g.
            # ...\\Python\\Python38\\Scripts. This prevents the aforementioned edge
            # case, and also prevents stuff like a pip-installed "ping.exe" from
            # being used instead of the Windows ping.exe.
            new_path = []
            for path in self.PATH:
                if "\\getmac\\Scripts" not in path and not (
                    "\\Python" in path and "\\Scripts" in path
                ):
                    new_path.append(path)

            self.PATH = new_path

        # Rebuild the combined PATH string after modifications are made
        # This will be used with shutil.which() for PATH lookups
        self.PATH_STR = os.pathsep.join(self.PATH)


settings: Final[Settings] = Settings()
consts: Final[Constants] = Constants()
gvars: Final[Variables] = Variables()
