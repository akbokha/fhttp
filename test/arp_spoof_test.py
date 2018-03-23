from arp_spoof import ArpSpoof
from ip_to_mac_mapper import IpToMacMapper
from network_discoverer import NetworkDiscoverer

arp = ArpSpoof('enp0s3', '192.168.56.101', '192.168.56.102')
network_discoverer = NetworkDiscoverer()

# Mocking the ip to mac mapper.
mapping = IpToMacMapper().set_all({
    '192.168.56.101': '08:00:27:B0:A1:AB',
    '192.168.56.102': '08:00:27:C6:A4:61',
})
arp.start()
arp.join()

# @todo Convert into an automated test