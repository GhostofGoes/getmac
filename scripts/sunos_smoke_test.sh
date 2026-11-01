#!/bin/sh
# Smoke test for Oracle Solaris and illumos, run in VMs by .github/workflows/sunos.yml.
#
# Runs getmac from this checkout as root and as a regular user, and checks that
# the MACs it finds match the ones the system's own commands report. It needs root,
# since it adds datalinks (a VNIC, which zones usually have, an aggregation, and a VLAN)
# and a user to the system.
set -u
PATH=/usr/sbin:/usr/bin:$PATH
export PATH
cd "$(dirname "$0")/.." || exit 1
SRC=$(pwd)
FAILED=0
TEST_USER=gmtest  # illumos warns about names over 8 characters

# "52:54:0:12:34:56" -> "52:54:00:12:34:56"
normalize() {
    python3 -c "import sys; print(':'.join('%02x' % int(o, 16) for o in sys.argv[1].split(':')))" "$1"
}

check() {
    description=$1
    expected=$(normalize "$2")
    shift 2
    for user in root "$TEST_USER"; do
        if [ "$user" = root ]; then
            result=$(env PYTHONPATH="$SRC" python3 -m getmac "$@" 2>/dev/null)
        else
            result=$(su "$TEST_USER" -c "PATH=$PATH PYTHONPATH=$SRC python3 -m getmac $*" 2>/dev/null)
        fi
        if [ "$result" = "$expected" ]; then
            echo "PASS: $description ($user): $result"
        else
            echo "FAIL: $description ($user): expected '$expected', got '$result'"
            echo "Debug output for 'getmac -d $*' as $user:"
            if [ "$user" = root ]; then
                env PYTHONPATH="$SRC" python3 -m getmac -d "$@" 2>&1
            else
                su "$TEST_USER" -c "PATH=$PATH PYTHONPATH=$SRC python3 -m getmac -d $*" 2>&1
            fi
            FAILED=1
        fi
    done
}

# Stop if a value the checks depend on is empty, so the failure says why
require() {
    if [ -z "$2" ]; then
        echo "FAIL: couldn't find the $1"
        exit 1
    fi
}

# Wait until an address is usable (not "tentative" while duplicate address detection runs)
wait_for_addr() {
    tries=0
    while [ "$(ipadm show-addr -p -o state "$1")" != ok ]; do
        tries=$((tries + 1))
        if [ "$tries" -gt 30 ]; then
            echo "FAIL: address $1 isn't usable"
            ipadm show-addr "$1"
            exit 1
        fi
        sleep 1
    done
}

uname -a
cat /etc/release
python3 -VV

useradd "$TEST_USER" || exit 1
chmod -R a+rX "$SRC"

IFACE=$(route -n get default | awk '/interface:/ {print $2}')
GATEWAY=$(route -n get default | awk '/gateway:/ {print $2}')
IFACE_MAC=$(dladm show-phys -m -p -o address "$IFACE")
require "default interface" "$IFACE"
require "default gateway" "$GATEWAY"
require "MAC of $IFACE" "$IFACE_MAC"
echo "Default interface: $IFACE ($IFACE_MAC), gateway: $GATEWAY"

# A VNIC with an IPv6 link-local address, which is also a neighbor of the NIC
dladm create-vnic -l "$IFACE" vnic0 || exit 1
ipadm create-ip vnic0 || exit 1
ipadm create-addr -T addrconf vnic0/v6 || exit 1
VNIC_MAC=$(dladm show-vnic -p -o macaddress vnic0)
VNIC_IP6=$(ipadm show-addr -p -o addr vnic0/v6 | sed 's|/.*||; s|%.*||')
require "MAC of vnic0" "$VNIC_MAC"
require "IPv6 address of vnic0" "$VNIC_IP6"
echo "VNIC: vnic0 ($VNIC_MAC), $VNIC_IP6"
ping "$GATEWAY" 3 || exit 1
# The NIC needs an IPv6 address to send the ping from (it already has one on Solaris)
ipadm create-addr -T addrconf "$IFACE/v6" 2>/dev/null
wait_for_addr vnic0/v6
ping -A inet6 -i "$IFACE" "$VNIC_IP6" 3 || exit 1
# "arp <ip>" prints "<host> (<ip>) at <mac>", or "<ip> (<ip>) -- no entry" if it isn't there
GATEWAY_MAC=$(arp "$GATEWAY" | awk '$3 == "at" {print $4}')
require "MAC of the gateway" "$GATEWAY_MAC"

# A link aggregation of two simulated NICs (the VM only has one NIC), and a VLAN on the NIC.
# They're temporary (-t), so they don't have IP interfaces or show up in ifconfig.
dladm create-simnet -t simnet0 || exit 1
dladm create-simnet -t simnet1 || exit 1
dladm create-aggr -t -l simnet0 -l simnet1 aggr0 || exit 1
dladm create-vlan -t -l "$IFACE" -v 5 vlan5 || exit 1
# The aggregation's own MAC is on the line without a port ("--")
AGGR_MAC=$(dladm show-aggr -x aggr0 | awk '$2 == "--" {print $6}')
require "MAC of aggr0" "$AGGR_MAC"
echo "Aggregation: aggr0 ($AGGR_MAC), VLAN: vlan5"

check "default interface" "$IFACE_MAC"
check "interface $IFACE" "$IFACE_MAC" -i "$IFACE"
check "VNIC vnic0" "$VNIC_MAC" -i vnic0
check "aggregation aggr0" "$AGGR_MAC" -i aggr0
check "VLAN vlan5" "$IFACE_MAC" -i vlan5
check "gateway $GATEWAY" "$GATEWAY_MAC" -4 "$GATEWAY" -N
check "IPv6 neighbor $VNIC_IP6" "$VNIC_MAC" -6 "$VNIC_IP6" -N
check "IPv6 neighbor $VNIC_IP6%$IFACE" "$VNIC_MAC" -6 "$VNIC_IP6%$IFACE" -N

if [ "$FAILED" -ne 0 ]; then
    echo "Some checks failed"
    exit 1
fi
echo "All checks passed"
