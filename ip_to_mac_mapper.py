# fhttp - An application which is capable of exploiting techniques such as ARP cache poisoning,
# and which uses the positions acquired by exploiting these vulnerabilities for things such as stealing insecure cookies
# Abdel K. Bokharouss & Adriaan Knapen
# MIT license

# IP to MAC record object

class IpToMacMapper:

    def __init__(self):
        self._ip_to_mac = {}

    def set_all(self, ip_to_mac):
        # type: (dict) -> self
        self._ip_to_mac = {}
        for ip in ip_to_mac:
            self.set(ip, ip_to_mac[ip])

        return self

    def set(self, ip, mac):
        # type: (str, str) -> self
        self._ip_to_mac[ip] = mac.lower()
        return self

    def get_all(self):
        # type: () -> dict
        return self._ip_to_mac

    def get(self, ip):
        # type: (str) -> str or None
        if ip in self._ip_to_mac:
            return self._ip_to_mac[ip]

        return None

