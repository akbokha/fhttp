from ip_to_mac import IPtoMACDict

import scapy.config
import scapy.route
from scapy.all import *
import scapy.layers.l2


class NetworkDiscoverer:
    local_host = '127.0.0.1'
    non_routable = '0.0.0.0'
    def_mask = 0xFFFFFFFF

    def __init__(self):
        self.host_mac = self.ip_address = self.ip_to_mac_record = None
        try:
            self.host_mac = self.get_own_mac_address()
        except Exception as e:
            print(e)
            sys.exit(1)
        self.ip_address = self.get_own_ip_address()

    """
    Return own mac_addresss
    @rtype: str
    @return: mac address
    """

    def get_own_mac_address(self, update=False):
        if self.host_mac is not None and not update:
            return self.host_mac
        macs = [get_if_hwaddr(i) for i in get_if_list()]
        for mac in macs:
            if mac != "00:00:00:00:00:00":
                return mac
        raise Exception("Failed to obtain local mac address")

    """
    Return own ip_address
    @rtype: str
    @return: ip address
    """

    def get_own_ip_address(self, update=False):
        if self.ip_address is not None and not update:
            return self.ip_address
        return socket.gethostbyname(socket.gethostname())

    def get_ip_to_mac_mapping(self, new_scan=False):
        if self.ip_to_mac_record is not None and not new_scan:
            return self.ip_to_mac_record
        else:
            return self.scan_local_network()

    """
    courtesy of the script shared by Benedikt Waldvogel at stackOverFlow: 
    https://stackoverflow.com/questions/207234/list-of-ip-addresses-hostnames-from-local-network-in-python/
    """

    def to_CIDR_notation(self, network_bytes, netmask_bytes):
        network = scapy.utils.ltoa(network_bytes)
        netmask = 32 - int(round(math.log(self.def_mask - netmask_bytes, 2)))
        return "%s/%s" % (network, netmask)

    def scan_local_network(self):
        ip_mac_pairs = {}
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
                            ip_mac_pairs[r.psrc] = r.hwsrc
                        except socket.herror:
                            pass  # did not resolve
                except socket.error as err:
                    if err.errno == errno.EPERM:  # no root? (classic Abdel move)
                        print('no permission - did you run it with root permissions?')
                    else:
                        raise  # other error type
            self.ip_to_mac_record = IPtoMACDict(ip_mac_pairs)
            return self.ip_to_mac_record