import logging
import os
import platform
import sys
from typing import Dict, List


# TODO: methods to print, dump, etc variables
# TODO: type validation?
class VarsClass:
    pass


class Settings(VarsClass):
    """
    User-configurable settings.
    """

    #: Debugging level. Increased value => more output. 4 is roughly the highest.
    DEBUG: int = 0

    #: UDP port to use for populating the ARP table
    PORT: int = 55555

    #: User-configurable override to force a specific platform
    # TODO: This will change to a function argument in 1.0.0
    OVERRIDE_PLATFORM: str = ""

    #: Force a specific method to be used for all lookups
    #: Used for debugging and testing
    FORCE_METHOD: str = ""


class Constants(VarsClass):
    """
    Platform identifiers and other constants.
    """

    _UNAME: platform.uname_result = platform.uname()
    _SYST: str = _UNAME.system
    WINDOWS: bool = _SYST == "Windows"
    DARWIN: bool = _SYST == "Darwin"
    OPENBSD: bool = _SYST == "OpenBSD"
    FREEBSD: bool = _SYST == "FreeBSD"
    NETBSD: bool = _SYST == "NetBSD"
    SOLARIS: bool = _SYST == "SunOS"
    #: Not including Darwin or Solaris as a "BSD"
    BSD: bool = OPENBSD or FREEBSD or NETBSD

    #: Windows Subsystem for Linux (WSL)
    #: WSL1: abstraction layer remapping Linux syscalls to Windows syscalls
    #: WSL2: fancy Linux VM on Hyper-V
    WSL1: bool = (
        _SYST == "Linux"
        and "Microsoft" in _UNAME.version
        and "-WSL2" not in _UNAME.release
    )
    WSL2: bool = (
        _SYST == "Linux"
        and "Microsoft" not in _UNAME.version
        and "-WSL2" in _UNAME.release
    )
    LINUX: bool = _SYST == "Linux" and not WSL1

    #: NOTE: "Linux" methods apply to Android without modifications
    #: If there's Android-specific stuff then we can add a platform
    #: identifier for it.
    ANDROID: bool = (
        hasattr(sys, "getandroidapilevel") or "ANDROID_STORAGE" in os.environ
    )

    #: Generic platform identifier used for filtering methods
    # TODO: change to "wsl1", since WSL2 method should just work like normal linux
    PLATFORM: str = "wsl" if (LINUX and WSL1) else _SYST.lower()

    MAC_RE_COLON: str = r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"
    MAC_RE_DASH: str = r"([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})"
    #: On OSX, some MACs in arp output may have a single digit instead of two
    #: Examples: "18:4f:32:5a:64:5", "14:cc:20:1a:99:0"
    #: This can also happen on other platforms, like Solaris
    MAC_RE_SHORT: str = r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})"


class Variables(VarsClass):
    """
    Things that can change. Essentially most of the global variables in getmac.
    """

    #: Get and cache the configured system PATH on import
    #: The process environment does not change after a process is started
    PATH: List[str] = os.environ.get("PATH", os.defpath).split(os.pathsep)
    PATH_STR: str = os.pathsep.join(PATH)

    #: Use a copy of the environment so we don't
    #: modify the process's current environment.
    ENV: Dict[str, str] = dict(os.environ)

    #: Cache of commands that have been checked for existence by check_command()
    CHECK_COMMAND_CACHE: Dict[str, bool] = {}

    #: Configure logging
    log = logging.getLogger("getmac")  # type: logging.Logger

    #: Default interface
    DEFAULT_IFACE: str = ""

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


settings = Settings()
consts = Constants()
gvars = Variables()
