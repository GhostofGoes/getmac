"""
Global variables, constants, and settings for the getmac package.
"""

import logging
import ntpath
import os
import platform
import sys
from typing import Final


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

    Methods for this platform are used instead of the methods for the detected
    platform, :attr:`~getmac.variables.Constants.PLATFORM`. Use a platform
    identifier such as ``"linux"`` or ``"wsl"``, or any value returned by
    :func:`platform.system`, such as ``"Darwin"``. Case and surrounding
    whitespace are ignored. An empty string (the default) means no override.
    """

    FORCE_METHOD: str = ""
    """
    Force a specific method to be used for all lookups.
    Used for debugging and testing.
    """

    # Added for https://github.com/GhostofGoes/getmac/issues/101
    ARP_TIMEOUT: float = 0
    """
    How long to keep checking the ARP table (IPv4) or NDP list (IPv6) for a host,
    in seconds, after sending the UDP packet to populate it
    (see :attr:`~getmac.variables.Settings.PORT`).

    The host's entry is only added once it replies, which often takes longer than
    getmac takes to check the table. If it isn't there, getmac checks again with
    short, growing delays until the host is found or this much time has passed.
    Lookups of hosts that don't reply take this much longer.
    ``0`` (the default) checks once, without waiting.

    This doesn't apply when getmac sends an ARP request itself and waits for the reply
    instead (:class:`~getmac.getmac.ArpingHost` or :class:`~getmac.getmac.CtypesHost`).
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
        _SYST == "Linux" and "Microsoft" in _UNAME.version and "-WSL2" not in _UNAME.release
    )
    """
    Windows Subsystem for Linux (WSL) version 1.
    The version that's a very cool abstraction layer
    remapping Linux syscalls to Windows syscalls.

    Its kernel release and version contain ``Microsoft``, e.g. ``4.4.0-19041-Microsoft``.
    On WSL1, :attr:`~getmac.variables.Constants.PLATFORM` is ``"wsl"``
    and :attr:`~getmac.variables.Constants.LINUX` is :obj:`False`.

    :meta hide-value:
    """

    WSL2: Final[bool] = (
        _SYST == "Linux"
        and "Microsoft" not in _UNAME.version
        and ("-WSL2" in _UNAME.release or "microsoft-standard" in _UNAME.release)
    )
    """
    Windows Subsystem for Linux (WSL) version 2.
    The version that's basically a fancy Linux VM on Hyper-V.

    Its kernel release ends with ``-microsoft-standard-WSL2``, or with
    ``-microsoft-standard`` on older (4.19) kernels. WSL2 uses the Linux methods,
    so :attr:`~getmac.variables.Constants.PLATFORM` is ``"linux"``
    and :attr:`~getmac.variables.Constants.LINUX` is :obj:`True`.

    :meta hide-value:
    """

    LINUX: Final[bool] = _SYST in ("Linux", "Android") and not WSL1
    """
    If the system is running Linux (excluding WSL1), including Android.

    :meta hide-value:
    """

    ANDROID: Final[bool] = hasattr(sys, "getandroidapilevel") or "ANDROID_STORAGE" in os.environ
    """
    .. note::
       "Linux" methods apply to Android without modifications.
       If there's Android-specific stuff then we can add a platform
       identifier for it.

    :meta hide-value:
    """

    # TODO: change "wsl" to "wsl1", since WSL2 method should just work like normal linux
    # Android uses the Linux methods. platform.system() is "Linux" on Android before
    # Python 3.13, and "Android" on Python 3.13 and newer.
    PLATFORM: Final[str] = "wsl" if WSL1 else "linux" if _SYST == "Android" else _SYST.lower()
    """
    Generic platform identifier used for filtering methods.

    Possible values:

    - wsl (WSL1 only, see :attr:`~getmac.variables.Constants.WSL1`. WSL2 is ``linux``.)
    - linux (including Android)
    - windows
    - darwin
    - openbsd
    - freebsd
    - netbsd
    - sunos
    - hp-ux
    - Any other values that can be returned by :func:`platform.system`,
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

    PATH: list[str] = os.environ.get("PATH", os.defpath).split(os.pathsep)
    """
    Get and cache the configured system PATH environment variable on import.
    The process environment does not change after a process is started.

    :meta hide-value:
    """

    ENV: dict[str, str] = dict(os.environ)
    """
    Use a copy of the environment so any modifications that need to be made
    for operation of getmac doesn't modify the process's current environment.

    :meta hide-value:
    """

    CHECK_COMMAND_CACHE: dict[str, bool] = {}
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
            # Remove Python "Scripts" folders, e.g. ...\\Python\\Python313\\Scripts or a
            # virtual environment's .venv\\Scripts. Otherwise our script "getmac.exe"
            # could be found ahead of the actual Windows getmac.exe, and something like
            # a pip-installed "ping.exe" could be used instead of the Windows ping.exe.
            self.PATH = [
                path
                for path in self.PATH
                if ntpath.basename(ntpath.normpath(path)).lower() != "scripts"
            ]


settings: Final[Settings] = Settings()
consts: Final[Constants] = Constants()
gvars: Final[Variables] = Variables()
