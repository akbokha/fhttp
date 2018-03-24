from scapy.layers.inet import TCP, IP
from scapy.layers.l2 import Ether

from PacketHandler.Filters.http_200_filter import Http200Filter
from PacketHandler.Injectors.abstract_injector import AbstractInjector
import re

class ImgTagInjector(AbstractInjector):


    def __init__(self):
        super(ImgTagInjector, self).__init__()
        self._filter = Http200Filter()

    def inject(self, packet):
        # type: (Ether) -> Ether or None
        if not self._filter.is_filtered(packet):
            return

        payload = re.sub('<body>', '\0<img url="http://blabla.com">', str(packet[TCP].payload), 1, re.IGNORECASE)
        del packet[TCP].chksum
        del packet[IP].chksum
        del packet[IP].len
        packet[TCP].remove_payload()
        packet[TCP].add_payload(payload)
        packet[TCP].build()

        print('! Injected image tag')

        return packet