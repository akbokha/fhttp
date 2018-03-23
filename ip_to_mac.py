# fhttp - An application which is capable of exploiting techniques such as ARP cache poisoning,
# and which uses the positions acquired by exploiting these vulnerabilities for things such as stealing insecure cookies
# Abdel K. Bokharouss & Adriaan Knapen
# MIT license

# IP to MAC record object

class IPtoMACDict():

    ip_to_mac = {}

    def __init__(self, ip_mac_pairs=None):
        self.ip_to_mac = ip_mac_pairs

    def set_ip_to_mac_dict(self, ip_to_mac):
        self.ip_to_mac = ip_to_mac

    def get_ip_to_mac_dict(self):
        return self.ip_to_mac