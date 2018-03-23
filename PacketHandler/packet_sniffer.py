import threading

from scapy.all import sniff
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether, sendp

from PacketHandler.Filters.composite_filter import CompositeFilter


class PacketSniffer(threading.Thread):

    def __init__(self, attacker_ips, ip_to_mac, network_interface):
        super(PacketSniffer, self).__init__()
        self._network_interface = network_interface
        self._attacker_ips = attacker_ips
        self._ip_to_mac = ip_to_mac

        self._stored_packets = []
        # self.packet_filter = CompositeFilter()
        self.packet_injector = []

    def run(self):
        sniff(
            iface=self._network_interface,
            store=0,
            # packet_filter="tcp and port 80", # @todo move this filtering to a later point in time, filtering here would break the victims network
            prn=self.handle_packet
        )

    def get_stored_packets(self):
        return self._stored_packets

    def handle_packet(self, packet):
        """
        :param Ether packet:
        :return:
        """

        if self.packet_filter.is_filtered(packet):
            # self._stored_packets.append(packet)
            pass


        # Only consider packets with an IP part.
        if IP in packet:
            # Try to lookup the actual mac address of the package
            if packet[IP].dst not in self._ip_to_mac:
                print('received a packet for an unknown host (%s)' % packet[IP].dst)
            else:
                target_dst = self._ip_to_mac[packet[IP].dst]

                # Ignore packets target towards our self or already correctly targeted packets, since either we generated
                # them or they are legitimate packets originating from our own host.
                if packet[IP].dst not in self._attacker_ips and target_dst != packet.dst:
                    print('redirecting a packet from %s (%s) to %s' % (packet.dst, packet[IP].dst, target_dst))
                    packet.dst = target_dst
                    sendp(packet)
