"""
Utility and helper functions. These are basic in functionality
and should be relatively standalone. They are intended for
internal use by getmac.
"""

import os
import re
import shlex
import socket
import subprocess
from typing import Optional, Union

from .variables import consts, gvars, settings


def find_executable(command: str) -> Optional[str]:
    """
    Find the absolute path of a command by searching the directories in
    :data:`getmac.variables.Variables.PATH`.

    Only absolute directories are searched, and the current directory is never
    searched, even on Windows (where :func:`shutil.which` otherwise checks it first).
    This avoids running an executable planted in the working directory, or one
    reached through a relative or empty ``PATH`` entry
    (`GitHub issue #51 <https://github.com/GhostofGoes/getmac/issues/51>`__).

    Args:
        command: command to find, e.g. ``ip`` or ``arp.exe``

    Returns:
        The absolute path of the executable, or :obj:`None` if it wasn't found
    """
    if consts.WINDOWS:
        # On Windows, a command is run with its extension, e.g. "arp" -> "arp.exe".
        # PATHEXT lists the extensions to try, in order. A command that already has
        # an extension (e.g. "arp.exe") is matched by the bare name first.
        exts = [ext for ext in os.environ.get("PATHEXT", ".EXE").split(os.pathsep) if ext]
        names = [command, *(command + ext for ext in exts)]
    else:
        names = [command]

    for directory in gvars.PATH:
        if not os.path.isabs(directory):
            continue
        for name in names:
            candidate = os.path.join(directory, name)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate

    return None


def check_command(command: str) -> bool:
    """
    Check if a command exists, using :func:`find_executable`. The result of the
    check is cached in a global :class:`dict` to speed up subsequent lookups.

    Args:
        command: command to check

    Returns:
        If the command exists
    """
    if command not in gvars.CHECK_COMMAND_CACHE:
        gvars.CHECK_COMMAND_CACHE[command] = find_executable(command) is not None
    return gvars.CHECK_COMMAND_CACHE[command]


def check_path(filepath: str) -> bool:
    """
    Check if the file pointed to by ``filepath`` exists and is readable.

    Args:
        filepath: absolute path of file to check

    Returns:
        If the filepath exists and is readable
    """
    return os.path.exists(filepath) and os.access(filepath, os.R_OK)


def clean_mac(mac: Optional[str]) -> Optional[str]:
    """
    Check and format a string result to be lowercase colon-separated MAC.

    It will clean out any garbage and ensure the length and colons are correct,
    and replace ``-`` characters with ``:`` characters.

    If string is invalid after as much cleanup as possible, then :obj:`None`
    is returned. The specific issue is logged as a warning.

    Args:
        mac: MAC address string to clean

    Returns:
        Cleaned and formatted MAC address string, or :obj:`None` if
        validation failed.
    """
    if mac is None:
        return None

    # Handle cases where it's bytes
    if isinstance(mac, bytes):
        mac = mac.decode("utf-8")

    # Strip bad characters
    for garbage_string in ["\\n", "\\r"]:
        mac = mac.replace(garbage_string, "")

    # Remove trailing whitespace, make lowercase, remove spaces,
    # and replace dashes '-' with colons ':'.
    mac = mac.strip().lower().replace(" ", "").replace("-", ":")

    # Fix cases where there are no colons
    if ":" not in mac and len(mac) == 12:
        gvars.log.debug(f"Adding colons to MAC {mac}")
        mac = ":".join(mac[i : i + 2] for i in range(0, len(mac), 2))

    # Pad single-character octets with a leading zero (e.g. Darwin's ARP output)
    elif len(mac) < 17:
        gvars.log.debug(
            f"Length of MAC {mac} is {len(mac)}, padding single-character octets with zeros"
        )
        parts = mac.split(":")
        new_mac = []
        for part in parts:
            if len(part) == 1:
                new_mac.append("0" + part)
            else:
                new_mac.append(part)
        mac = ":".join(new_mac)

    # MAC address should ALWAYS be 17 characters before being returned
    if len(mac) != 17:
        gvars.log.warning(f"MAC address {mac} is not 17 characters long!")
        mac = None
    elif mac.count(":") != 5:
        gvars.log.warning(f"MAC address {mac} is missing colon (':') characters")
        mac = None
    return mac


def read_file(filepath: str) -> Optional[str]:
    """
    Open and read a file.

    Args:
        filepath: Absolute path of the file to read

    Returns:
        Text contents of the file, or :obj:`None` if opening
        the file failed.
    """
    try:
        with open(filepath) as f:
            return f.read()
    except OSError:
        gvars.log.debug(f"Could not find file: '{filepath}'")
        return None


def search(regex: str, text: str, group_index: int = 0, flags: int = 0) -> Optional[str]:
    """
    Search for a regular expression in a string, and return the specified group.
    This is thin wrapper around :func:`re.search` with some error handling.

    Args:
        regex: regular expression
        text: data to search
        group_index: index of value in the ``groupdict`` to return,
            if there are multiple groups in the regex
        flags: flags to :mod:`re` functions, e.g. :const:`re.IGNORECASE`

    Returns:
        The result, or :obj:`None` if the parsing failed
        or nothing was specified to search.
    """
    if not text:
        if settings.DEBUG:
            gvars.log.debug("No text to _search()")
        return None

    match = re.search(regex, text, flags)
    if match:
        return match.groups()[group_index]

    return None


def popen(command: str, args: str = "", arg: Optional[str] = None) -> str:
    """
    Execute a command with arguments and return the stdout (stderr is discarded).

    Wrapper around :func:`getmac.utils.call_proc`, which resolves the command to an
    absolute path with :func:`find_executable` and adds some debug logging. This
    should be used instead of :func:`getmac.utils.call_proc`.

    Args:
        command: command to run, e.g. ``ping`` or ``ping.exe``
        args: fixed, trusted arguments to pass to the command, or an empty string if
            there are none. These are split into separate arguments on POSIX.
        arg: a single, possibly untrusted argument, such as an interface name or IP
            address. It's passed as exactly one argument and is never split, so it
            can't inject extra command-line arguments.

    Returns:
        stdout from the command (stderr is discarded)

    Raises:
        CalledProcessError: the command failed to execute
        FileNotFoundError: the command wasn't found in the PATH directories
    """
    executable = find_executable(command)
    if executable is None:
        # A method's test() checks the command exists before the method is used, so
        # this normally only happens if the command was removed in the meantime.
        raise FileNotFoundError(f"Command '{command}' not found in any PATH directory")

    if settings.DEBUG >= 3:
        gvars.log.debug(f"Running: '{executable} {args}' (arg: {arg!r})")

    return call_proc(executable, args, arg)


def call_proc(executable: str, args: str, arg: Optional[str] = None) -> str:
    """
    Wrapper around :func:`subprocess.check_output` with some
    logging and type conversion.

    The reason this and :func:`getmac.utils.popen` are separate
    functions is to make it easier to mock for unit tests.

    Args:
        executable: command to run
        args: fixed, trusted arguments to the command
        arg: a single, possibly untrusted argument, passed as exactly one argument
            (see :func:`popen`)

    Returns:
        stdout from the command (stderr is discarded)

    Raises:
        CalledProcessError: the command failed to execute
    """
    cmd: Union[str, list[str]]
    if consts.WINDOWS:
        # Windows takes a single command-line string. list2cmdline() quotes the
        # untrusted argument so it stays a single argument.
        cmd = executable + " " + args if args else executable
        if arg is not None:
            cmd += " " + subprocess.list2cmdline([arg])
    else:
        cmd = [executable, *shlex.split(args)]
        if arg is not None:
            cmd.append(arg)

    output: Union[str, bytes] = subprocess.check_output(
        cmd, stderr=subprocess.DEVNULL, env=gvars.ENV
    )

    if settings.DEBUG >= 4:
        gvars.log.debug(f"Output from '{executable}' command: {output!s}")

    if isinstance(output, str):
        return output

    try:
        return output.decode("utf-8")
    except UnicodeDecodeError:
        # Windows commands print in the console's OEM code page (e.g. cp850 on
        # French or Spanish systems), not UTF-8. Characters that still can't be
        # decoded are replaced, so the rest of the output can be parsed.
        return output.decode("oem" if consts.WINDOWS else "utf-8", errors="replace")


def fetch_ip_using_dns() -> str:
    """
    Determine the IP address of the default network interface.

    Sends a UDP packet to Cloudflare's DNS (``1.1.1.1``), which should go through
    the default interface. This populates the source address of the socket,
    which we then inspect and return.

    Returns:
        IP address of this system's default network interface as a string
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("1.1.1.1", 53))
        return s.getsockname()[0]
