from PacketHandler.Filters.cookie_filter import CookieFilter
from PacketHandler.packet_sniffer import PacketSniffer
from ip_to_mac_mapper import IpToMacMapper

# Mock the network mapping
mapping = IpToMacMapper().set_all({
    '192.168.56.101': '08:00:27:B0:A1:AB',
    '192.168.56.102': '08:00:27:C6:A4:61',
})

packet_sniffer = PacketSniffer(['192.168.56.103'], mapping, 'enp0s3')
packet_sniffer.packet_filter.attach(CookieFilter())
packet_sniffer.start()
packet_sniffer.join()

# @todo convert into an automated test
