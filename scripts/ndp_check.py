"""Temporary: runs NdpNeighbors against the live ndp table. Not for merging."""

import os
import re
import socket
import subprocess
import sys

sys.path.insert(0, os.getcwd())
from getmac.getmac import NdpNeighbors  # noqa: E402

iface = sys.argv[1]
method = NdpNeighbors()
print("python", sys.version.split()[0], "test():", method.test())
out = subprocess.run(["ndp", "-an"], capture_output=True, text=True).stdout
print(out)
index = socket.if_nametoindex(iface)
failures = 0
for line in out.splitlines()[1:]:
    parts = line.split()
    if len(parts) < 3:
        continue
    addr, lladdr = parts[0], parts[1]
    want = None
    if re.fullmatch(r"[0-9a-fA-F]{1,2}(:[0-9a-fA-F]{1,2}){5}", lladdr):
        want = ":".join(p.zfill(2) for p in lladdr.lower().split(":"))
    queries = [addr]
    if "%" in addr:
        base, scope = addr.split("%", 1)
        queries += [base]
        if scope == iface:
            queries.append(f"{base}%{index}")
    for q in queries:
        got = method.get(q)
        ok = got == want
        failures += not ok
        print(("OK  " if ok else "FAIL"), repr(q), "got", got, "want", want, "raw", lladdr)
print("failures:", failures)
sys.exit(1 if failures else 0)
