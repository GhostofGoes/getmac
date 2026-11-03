# SPDX-FileCopyrightText: 2017-2026 Christopher Goes
# SPDX-License-Identifier: MIT

"""
Fuzz tests, using Hypothesis to generate inputs.

getmac parses the output of system commands and files like ``/proc/net/arp``, and takes
IP addresses, hostnames and interface names from callers. These tests feed random and
mutated input to the parsers and the public API, and check that they return a MAC, an
interface name or :obj:`None`, and never raise an exception or run a command they shouldn't.

Each test runs a small number of examples during normal test runs. ``pdm run fuzz``
runs many more (the "fuzz" profile below).

Hypothesis ships compiled wheels that don't load on PyPy, so it isn't installed
there and these tests are skipped.
"""

import os
import re
from pathlib import Path

import pytest

pytest.importorskip("hypothesis", reason="Hypothesis isn't installed on PyPy")

from hypothesis import HealthCheck, example, given
from hypothesis import settings as hyp_settings
from hypothesis import strategies as st

from getmac import getmac, utils
from getmac.variables import consts, gvars

# A few examples during normal test runs, many more with "pdm run fuzz". The deadline
# is off because a slow CI runner can take longer than the default for an example,
# which isn't a bug.
hyp_settings.register_profile("default", max_examples=50, deadline=None)
hyp_settings.register_profile("fuzz", max_examples=5000, deadline=None)
hyp_settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))

SAMPLES_DIR = Path(__file__).parent / "samples"

# All command output and file samples, used as seeds that are mutated
SAMPLES = sorted(
    p.read_text(encoding="utf-8", errors="replace")
    for p in SAMPLES_DIR.rglob("*")
    if p.is_file() and not p.name.upper().startswith(("LICENSE", "README"))
)

# A MAC in any of the formats clean_mac() returns
CLEAN_MAC_RE = re.compile(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}")

# Pieces of real output, so generated text looks like what the parsers expect
TOKENS = [
    "00:50:56:f1:4c:50",
    "00-50-56-F1-4C-50",
    "0050.56f1.4c50",
    "0:50:56:f1:4c:5",
    "ff:ff:ff:ff:ff:ff",
    "192.168.16.2",
    "192.0.2.1",
    "fe80::1",
    "eth0",
    "ens33",
    "en0",
    "lo",
    "wlan0",
    "dev",
    "lladdr",
    "ether",
    "HWaddr",
    "address:",
    "Physical Address",
    "at",
    "on",
    "?",
    "(",
    ")",
    "[ether]",
    "REACHABLE",
    "STALE",
    "FAILED",
    "INCOMPLETE",
    "default",
    "via",
    "proto",
    "dhcp",
    "metric",
    "Iface",
    "Destination",
    "00000000",
    "0x0",
    "0x2",
    "0x6",
    "Link",
    "encap:Ethernet",
    "Unicast",
    "Reply",
    "from",
    "bytes",
    "interface:",
    "gateway:",
    "0.0.0.0",
    "UG",
    "UGS",
    "Address",
    "Gateway",
    "Interface",
    "Index",
    "Name",
    "=",
    ",",
    ":",
    "-",
    '"',
    "\t",
    " ",
    "  ",
    "\n",
    "\r\n",
]


@st.composite
def command_output(draw):
    """Random text, text built from pieces of real output, or a mutated sample."""
    kind = draw(st.sampled_from(["text", "tokens", "sample"]))
    if kind == "text":
        return draw(st.text())
    if kind == "tokens":
        return "".join(draw(st.lists(st.sampled_from(TOKENS) | st.text(max_size=5))))

    lines = draw(st.sampled_from(SAMPLES)).splitlines(keepends=True)
    for _ in range(draw(st.integers(0, 5))):
        if not lines:
            break
        i = draw(st.integers(0, len(lines) - 1))
        action = draw(st.sampled_from(["delete", "duplicate", "truncate", "insert", "swap"]))
        if action == "delete":
            del lines[i]
        elif action == "duplicate":
            lines.insert(i, lines[i])
        elif action == "truncate":
            lines[i] = lines[i][: draw(st.integers(0, len(lines[i])))]
        elif action == "insert":
            lines.insert(i, draw(st.text(max_size=40) | st.sampled_from(TOKENS)))
        else:
            j = draw(st.integers(0, len(lines) - 1))
            lines[i], lines[j] = lines[j], lines[i]
    return "".join(lines)


# Arguments the methods get: IPs, interface names, or anything else
method_args = st.sampled_from(TOKENS) | st.ip_addresses().map(str) | st.text(max_size=40)

# Methods that only parse command output or files. CtypesHost, FcntlIface and
# DefaultIfaceNetsh use OS APIs, and are tested separately with mocks.
PARSER_METHODS = [
    m
    for m in getmac.METHODS
    if m not in (getmac.CtypesHost, getmac.FcntlIface, getmac.DefaultIfaceNetsh)
]


@pytest.mark.parametrize("method_class", PARSER_METHODS, ids=lambda m: m.__name__)
@pytest.mark.parametrize("platform", ["linux", "darwin", "solaris"])
@given(data=command_output(), arg=method_args)
@hyp_settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_method_parsers(mocker, method_class, platform, data, arg):
    mocker.patch("getmac.utils.popen", return_value=data)
    mocker.patch("getmac.utils.read_file", return_value=data)
    mocker.patch.object(consts, "DARWIN", platform == "darwin")
    mocker.patch.object(consts, "SOLARIS", platform == "solaris")

    result = method_class().get(arg)

    assert result is None or isinstance(result, str)


# Text that looks like a MAC, or anything else
mac_like = (
    st.from_regex(r"\A[0-9a-fA-F]{1,2}([:-][0-9a-fA-F]{1,2}){5}\Z")
    | st.from_regex(r"\A[0-9a-fA-F]{12}\Z")
    | st.sampled_from(TOKENS)
    | st.text(max_size=30)
)


@given(mac=mac_like)
@example(mac="zz:zz:zz:zz:zz:zz")
@example(mac="00:11:22:33:44:55:")
def test_clean_mac(mac):
    """clean_mac() returns a lowercase colon-separated MAC or None, for str or UTF-8 bytes."""
    result = utils.clean_mac(mac)

    assert result is None or CLEAN_MAC_RE.fullmatch(result)
    assert utils.clean_mac(mac.encode("utf-8")) == result
    # Cleaning a clean MAC doesn't change it
    assert utils.clean_mac(result) == result


# Arguments as callers might pass them: valid addresses, names, or anything else
api_args = (
    st.none()
    | st.ip_addresses().map(str)
    | st.sampled_from(TOKENS)
    | st.text(max_size=40)
    | st.text(max_size=40).map(lambda s: s.encode("utf-8"))
)


def _methods_of_type(method_type):
    return [
        m
        for m in PARSER_METHODS
        if m.method_type == method_type
        or (m.method_type == "ip" and method_type in ("ip4", "ip6"))
    ]


@given(
    kwarg=st.sampled_from([None, "interface", "ip", "ip6", "hostname"]),
    value=api_args,
    network_request=st.booleans(),
    resolved=st.none() | st.ip_addresses(v=4).map(str) | st.text(max_size=20),
    methods=st.fixed_dictionaries(
        {t: st.sampled_from(_methods_of_type(t)) for t in getmac.METHOD_CACHE}
    ),
    data=command_output(),
)
@example(
    kwarg="ip",
    value="192.168.16.2",
    network_request=False,
    resolved=None,
    methods={
        "ip4": getmac.ArpFile,
        "ip6": getmac.IpNeighborShow,
        "iface": getmac.SysIfaceFile,
        "default_iface": getmac.DefaultIfaceLinuxRouteFile,
    },
    data="IP address  HW type  Flags  HW address  Mask  Device\n"
    "192.168.16.2  0x1  0x2  zz:zz:zz:zz:zz:zz  *  ens33\n",
)
@hyp_settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_get_mac_address(mocker, kwarg, value, network_request, resolved, methods, data):
    """
    get_mac_address() returns a clean MAC or None for any string argument, whatever
    the commands and files it reads return. Nothing is sent on the network, and the
    command output and files are generated.
    """
    mocker.patch("getmac.getmac.METHOD_CACHE", {t: m() for t, m in methods.items()})
    mocker.patch("getmac.getmac.FALLBACK_CACHE", {k: [] for k in getmac.FALLBACK_CACHE})
    mocker.patch.object(gvars, "DEFAULT_IFACE", "")
    mocker.patch("socket.socket")
    mocker.patch("time.sleep")
    if resolved is None:
        mocker.patch("socket.gethostbyname", side_effect=OSError("Name or service not known"))
    else:
        mocker.patch("socket.gethostbyname", return_value=resolved)
    mocker.patch("getmac.utils.popen", return_value=data)
    mocker.patch("getmac.utils.read_file", return_value=data)

    kwargs = {kwarg: value} if kwarg else {}
    result = getmac.get_mac_address(**kwargs, network_request=network_request)

    assert result is None or CLEAN_MAC_RE.fullmatch(result)
