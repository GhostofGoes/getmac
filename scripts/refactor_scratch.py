import logging
import sys
from getmac import rewrite
rewrite.DEBUG = 2

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

rewrite.initialize_method_cache("iface")
rewrite.initialize_method_cache("ip4")
rewrite.initialize_method_cache("ip6")
rewrite.initialize_method_cache("ip")
rewrite.initialize_method_cache("default_iface")

print(rewrite.METHOD_CACHE)
print(rewrite.FALLBACK_CACHE)

print(rewrite.get_by_method("ip4", "10.0.0.1"))
print(rewrite.get_by_method("ip4", "10.0.0.20"))
print(rewrite.get_by_method("ip4", "10.0.0.33"))
print(rewrite.get_by_method("iface", "Ethernet 4"))
print(rewrite.get_by_method("iface", "eth0"))
print(rewrite.get_by_method("iface", "enp1s0"))
print(rewrite.get_by_method("default_iface"))

print(rewrite.get_mac_address(ip="10.0.0.1"))
print(rewrite.get_mac_address(ip="10.0.0.20"))
print(rewrite.get_mac_address(ip="10.0.0.33"))
print(rewrite.get_mac_address(interface="Ethernet 4"))
print(rewrite.get_mac_address(interface="eth0"))
print(rewrite.get_mac_address(interface="enp1s0"))
print(rewrite.get_mac_address())
