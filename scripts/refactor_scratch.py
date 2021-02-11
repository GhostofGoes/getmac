import logging
import sys
from getmac import getmac
getmac.DEBUG = 2

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

getmac.initialize_method_cache("iface")
getmac.initialize_method_cache("ip4")
getmac.initialize_method_cache("ip6")
getmac.initialize_method_cache("ip")
getmac.initialize_method_cache("default_iface")

print(getmac.METHOD_CACHE)
print(getmac.FALLBACK_CACHE)

print(getmac.get_by_method("ip4", "10.0.0.1"))
print(getmac.get_by_method("ip4", "10.0.0.20"))
print(getmac.get_by_method("ip4", "10.0.0.33"))
print(getmac.get_by_method("iface", "Ethernet 4"))
print(getmac.get_by_method("iface", "eth0"))
print(getmac.get_by_method("iface", "enp1s0"))
print(getmac.get_by_method("default_iface"))

print(getmac.get_mac_address(ip="10.0.0.1"))
print(getmac.get_mac_address(ip="10.0.0.20"))
print(getmac.get_mac_address(ip="10.0.0.33"))
print(getmac.get_mac_address(interface="Ethernet 4"))
print(getmac.get_mac_address(interface="eth0"))
print(getmac.get_mac_address(interface="enp1s0"))
print(getmac.get_mac_address())
