#!/bin/sh
# Temporary: save FreeBSD command output for test samples, print it with checksums
mkdir -p out
save() {
  name=$1; shift
  "$@" > "out/$name.out" 2>/dev/null
  echo "=====BEGIN $name rc=$?"
  cat "out/$name.out"
  echo "=====END $name sha256=$(sha256 -q "out/$name.out")"
}
save freebsd-version freebsd-version
save route_get_default route get default
save route_-n_get_default route -n get default
save netstat_-r netstat -r
save netstat_-rn netstat -rn
if command -v python3 >/dev/null; then
  python3 -c "import sys; sys.path.insert(0, '.'); import getmac; from getmac import getmac as g; print('DEFAULT_IFACE', getmac.get_default_interface(), g.METHOD_CACHE['default_iface'])"
fi
GW=$(route -n get default | awk '/gateway:/ {print $2}')
route delete default >/dev/null
save route_-n_get_default_no_route route -n get default
save netstat_-rn_no_default_route netstat -rn
if command -v python3 >/dev/null; then
  python3 -c "import sys; sys.path.insert(0, '.'); import getmac; print('NO_ROUTE_DEFAULT_IFACE', getmac.get_default_interface())"
fi
route add default "$GW" >/dev/null
