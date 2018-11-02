import cProfile

code = """
from getmac import get_mac_address
a = get_mac_address()
b = get_mac_address(interface='Ethernet 4')
c = get_mac_address(interface='Ethernet 1')
d = get_mac_address(ip='10.0.0.1')
e = get_mac_address(hostname='localhost')
updated_mac = get_mac_address(ip="10.0.0.1", network_request=True)
"""
cProfile.run(code, 'testing.prof')
