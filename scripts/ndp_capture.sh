#!/bin/sh
# Temporary: captures real ndp output and checks NdpNeighbors live. Not for merging.
export PATH="$PATH:/sbin:/usr/sbin:/usr/pkg/bin:/usr/local/bin"
name="$1"
out="/tmp/ndp_samples/$name"
mkdir -p "$out"
cap() {
    # cap <file> <command...>: save stdout+stderr and the exit status
    f="$1"; shift
    "$@" > "$out/$f" 2>&1
    echo "rc=$? : $*" >> "$out/commands.txt"
}
uname -a > "$out/uname.txt"
route -n get default > "$out/route_-n_get_default.out" 2>&1
iface=$(awk '/interface:/ {print $2}' "$out/route_-n_get_default.out")
[ -n "$iface" ] || iface=$(netstat -rn -f inet 2>/dev/null | awk '$1 == "default" {print $NF; exit}')
echo "iface=$iface" >> "$out/commands.txt"

cap ndp_-an_before.out ndp -an
cap ifconfig_iface_before.out ifconfig "$iface"
ping6 -n -c 2 "ff02::1%$iface" > /dev/null 2>&1
ping6 -n -c 2 "ff02::2%$iface" > /dev/null 2>&1
cap ndp_-an_after_ping.out ndp -an

# A ULA prefix on the interface and static neighbors, so there are entries even
# when the VM's network has no IPv6 neighbors
ifconfig "$iface" inet6 fd00:6e64:7000::1 prefixlen 64 alias >> "$out/commands.txt" 2>&1 \
    || ifconfig "$iface" inet6 fd00:6e64:7000::1/64 alias >> "$out/commands.txt" 2>&1
sleep 3
cap ndp_-s_global.out ndp -s fd00:6e64:7000::10 02:00:5e:0a:0b:0c
cap ndp_-s_linklocal.out ndp -s "fe80::a0b:c0d%$iface" 02:00:5e:10:20:30
ping6 -n -c 1 fd00:6e64:7000::1 > /dev/null 2>&1
cap ndp_-an.out ndp -an
cap ndp_-a.out ndp -a
cap ndp_-n_fd00.out ndp -n fd00:6e64:7000::10
cap ifconfig_iface.out ifconfig "$iface"

if command -v python3 > /dev/null 2>&1; then py=python3; else py=$(ls /usr/local/bin/python3.* /usr/pkg/bin/python3.* 2>/dev/null | grep -v config | head -1); fi
echo "python=$py" >> "$out/commands.txt"
if [ -n "$py" ]; then
    $py -I scripts/ndp_check.py "$iface" > "$out/ndp_check.txt" 2>&1
    echo "rc=$? : ndp_check" >> "$out/commands.txt"
fi

for f in "$out"/*; do echo "===== $f"; cat "$f"; done
for f in "$out"/*; do sha256sum "$f" 2>/dev/null || sha256 "$f" 2>/dev/null || shasum -a 256 "$f"; done
echo "===== BEGIN TARBALL $name"
(cd /tmp/ndp_samples && tar cf - "$name" | gzip -9 | openssl base64)
echo "===== END TARBALL $name"
