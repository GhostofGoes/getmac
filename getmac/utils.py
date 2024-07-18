"""
Utility and helper functions. These are basic in functionality
and should be relatively standalone. They are intended for
internal use by getmac.
"""

import os
import re
import shlex
import socket
from shutil import which
from subprocess import DEVNULL, check_output
from typing import Optional, Union

from .variables import settings, consts, gvars


def check_command(command: str) -> bool:
    """
    Check if a command exists using :func:`shutil.which`. The result of the check
    is cached in a global dict to speed up subsequent lookups.

    Args:
        command: command to check

    Returns:
        If the command exists
    """
    if command not in gvars.CHECK_COMMAND_CACHE:
        gvars.CHECK_COMMAND_CACHE[command] = bool(which(command, path=gvars.PATH_STR))
    return gvars.CHECK_COMMAND_CACHE[command]


def check_path(filepath: str) -> bool:
    """
    Check if the file pointed to by `filepath` exists and is readable.

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


def search(
    regex: str, text: str, group_index: int = 0, flags: int = 0
) -> Optional[str]:
    """
    Search for a regular expression in a string, and return the specified group.
    This is thin wrapper around :func:`re.search` with some error handling.

    Args:
        regex: regular expression
        text: data to search
        group_index: what index in the ``groupdict`` to return,
            if there are more than 1
        flags: :mod:`re` flags

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


def popen(command: str, args: str) -> str:
    """
    Execute a command with arguments and return the stdout (stderr is discarded).

    Wrapper around :func:`~getmac.utils.call_proc`, with checks
    to ensure the command exists and is executable and some debug
    logging. This should be used instead of
    :func:`~getmac.utils.call_proc`.

    Args:
        command: command to run, e.g. ``ping`` or ``ping.exe``
        args: arguments to pass to the command, or empty string
            if there are no arguments.

    Returns:
        stdout from the command (stderr is discarded)

    Raises:
        CalledProcessError: the command failed to execute
    """
    for directory in gvars.PATH:
        executable = os.path.join(directory, command)
        # TODO: cache the result of these checks? these are system calls
        # and they can add up.
        if (
            os.path.exists(executable)
            and os.access(executable, os.F_OK | os.X_OK)
            and not os.path.isdir(executable)
        ):
            break
    else:
        executable = command

    if settings.DEBUG >= 3:
        gvars.log.debug(f"Running: '{executable} {args}'")

    return call_proc(executable, args)


def call_proc(executable: str, args: str) -> str:
    """
    Wrapper around :func:`subprocess.check_output` with some
    logging and type conversion. The reason this and
    :func:`~getmac.utils.popen` are separate functions is
    for testability.

    Args:
        executable: command to run
        args: arguments to the command

    Returns:
        stdout from the command (stderr is discarded)

    Raises:
        CalledProcessError: the command failed to execute
    """
    if consts.WINDOWS:
        cmd = executable + " " + args  # type: ignore
    else:
        cmd = [executable, *shlex.split(args)]  # type: ignore

    output: Union[str, bytes] = check_output(
        cmd, stderr=DEVNULL, env=gvars.ENV  # noqa: S603
    )

    if settings.DEBUG >= 4:
        gvars.log.debug(f"Output from '{executable}' command: {output!s}")

    if isinstance(output, bytes):
        output = output.decode("utf-8")

    return output


def uuid_convert(mac: int) -> str:
    """
    Convert value output from ``uuid`` internal function into a string.

    Args:
        mac: integer value returned from a ``uuid`` function

    Returns:
        String with colon-separated MAC address
    """
    return ":".join(("%012X" % mac)[i : i + 2] for i in range(0, 12, 2))


def fetch_ip_using_dns() -> str:
    """
    Determines the IP address of the default network interface.

    Sends a UDP packet to Cloudflare's DNS (``1.1.1.1``), which should go through
    the default interface. This populates the source address of the socket,
    which we then inspect and return.

    Returns:
        IP address of this system's default network interface as a string
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("1.1.1.1", 53))
        return s.getsockname()[0]
