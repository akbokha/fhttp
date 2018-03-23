import arp_spoof
import http_listener
from ip_to_mac_mapper import IpToMacMapper
from network_discoverer import NetworkDiscoverer

arp = arp_spoof.ArpSpoof('enp0s3', '192.168.56.101', '192.168.56.102')

# Mock the network mapping
mapping = IpToMacMapper().set_all({
    '192.168.56.101': '08:00:27:B0:A1:AB',
    '192.168.56.102': '08:00:27:C6:A4:61',
})

http_l = http_listener.HttpListener(mapping)
arp.start()
http_l.start()
arp.join()
http_l.join()