#!/bin/sh
# Smoke test for Oracle Solaris and illumos, run in VMs by .github/workflows/sunos.yml.
#
# Runs getmac from this checkout as root and as a regular user, and checks that
# the MACs it finds match the ones the system's own commands report. It needs root,
# since it adds a VNIC (what zones usually have) and a user to the system.
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

uname -a
cat /etc/release
python3 -VV

useradd "$TEST_USER" || exit 1
chmod -R a+rX "$SRC"

IFACE=$(route -n get default | awk '/interface:/ {print $2}')
GATEWAY=$(route -n get default | awk '/gateway:/ {print $2}')
IFACE_MAC=$(dladm show-phys -m -p -o address "$IFACE")
echo "Default interface: $IFACE ($IFACE_MAC), gateway: $GATEWAY"

# A VNIC with an IPv6 link-local address, which is also a neighbor of the NIC
dladm create-vnic -l "$IFACE" vnic0 || exit 1
ipadm create-ip vnic0 || exit 1
ipadm create-addr -T addrconf vnic0/v6 || exit 1
VNIC_MAC=$(dladm show-vnic -p -o macaddress vnic0)
VNIC_IP6=$(ipadm show-addr -p -o addr vnic0/v6 | sed 's|/.*||')
echo "VNIC: vnic0 ($VNIC_MAC), $VNIC_IP6"
ping "$GATEWAY" 3
# The NIC needs an IPv6 address to send the ping from (it already has one on Solaris)
ipadm create-addr -T addrconf "$IFACE/v6" 2>/dev/null
ping -A inet6 -i "$IFACE" "$VNIC_IP6" 3
GATEWAY_MAC=$(arp "$GATEWAY" | awk '{print $4}')

check "default interface" "$IFACE_MAC"
check "interface $IFACE" "$IFACE_MAC" -i "$IFACE"
check "VNIC vnic0" "$VNIC_MAC" -i vnic0
check "gateway $GATEWAY" "$GATEWAY_MAC" -4 "$GATEWAY" -N
check "IPv6 neighbor $VNIC_IP6" "$VNIC_MAC" -6 "$VNIC_IP6" -N

if [ "$FAILED" -ne 0 ]; then
    echo "Some checks failed"
    exit 1
fi
echo "All checks passed"
