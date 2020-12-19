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

print(rewrite.CACHE)
print(rewrite.FALLBACK_CACHE)

print(rewrite.get("ip4", "10.0.0.1"))
print(rewrite.get("iface", "Ethernet 4"))
print(rewrite.get("default_iface"))
