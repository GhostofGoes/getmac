#!/bin/sh
# Temporary: print FreeBSD command output for test samples
run() {
  echo "=====BEGIN $*"
  "$@"
  echo "=====END rc=$? $*"
}
run freebsd-version
run uname -a
run route get default
run route -n get default
run route -n get -inet6 default
run netstat -r
run netstat -rn
run ifconfig
python3 -c "import sys; sys.path.insert(0, '.'); import getmac; from getmac import getmac as g; print('DEFAULT_IFACE', getmac.get_default_interface()); print('MAC', getmac.get_mac_address()); print('METHOD', g.METHOD_CACHE['default_iface'])"
GW=$(route -n get default | awk '/gateway:/ {print $2}')
route delete default
run route -n get default
run netstat -rn
python3 -c "import sys; sys.path.insert(0, '.'); import getmac; print('NO_ROUTE_DEFAULT_IFACE', getmac.get_default_interface())"
route add default "$GW"
