from arp_spoof import ArpSpoof

arp = ArpSpoof('192.168.56.101', '192.168.56.102')

arp.start()
arp.join()

# @todo Convert into an automated test
