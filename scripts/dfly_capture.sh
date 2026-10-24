#!/bin/sh
# Temporary: captures real DragonFly BSD command output and checks getmac live. Not for merging.
export PATH="$PATH:/sbin:/usr/sbin:/usr/local/bin"
name="$1"
out="/tmp/dfly/$name"
mkdir -p "$out"
uname -a > "$out/uname.txt"
python3 -c 'import platform, sys; print(platform.system(), platform.release(), platform.version(), sys.version)' >> "$out/uname.txt" 2>&1
route=$(route -n get default)
iface=$(echo "$route" | awk '/interface:/ {print $2}')
gateway=$(echo "$route" | awk '/gateway:/ {print $2}')
echo "iface=$iface gateway=$gateway" >> "$out/uname.txt"
ping -n -c 1 "$gateway" > /dev/null 2>&1
# Static ARP entry for a fake host, to see the format of a static entry
arp -s 192.168.122.77 02:00:5e:0a:0b:0c >> "$out/uname.txt" 2>&1
python3 scripts/collect_samples.py --name collect --output-root "$out" > "$out/collect_stdout.txt" 2>&1
echo "collect rc=$?" >> "$out/uname.txt"
for c in "arp -n $gateway" "arp -an" "arp -n 192.168.122.77" "arp -n 192.168.122.99" "netstat -rn -f inet" "netstat -rn -f inet6" "route -n get -inet6 default" "ifconfig -l" "netstat -inW"; do
    f=$(echo "$c" | tr ' /' '__')
    $c > "$out/x_$f.out" 2>&1; echo "rc=$? : $c" >> "$out/uname.txt"
done
# What getmac (main) does today, falling back to the "other" methods
for a in "-dd" "-dd -i $iface" "-dd -4 $gateway" "-dd -4 192.168.122.77" "-dd -i lo0"; do
    echo "=== getmac $a" >> "$out/getmac_main.txt"
    python3 -m getmac $a >> "$out/getmac_main.txt" 2>&1; echo "rc=$?" >> "$out/getmac_main.txt"
done
python3 -c 'import getmac; print(getmac.get_default_interface())' >> "$out/getmac_main.txt" 2>&1
cd "$out" && find . -type f | sort | while read -r f; do echo "===== $f"; cat "$f"; done
find . -type f | sort | xargs sha256
