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
        # type: (Ether) -> Ether
        if not self._filter.is_filtered(packet):
            return None

        payload = str(packet[TCP].payload)
        packet[TCP].payload = re.sub('<body>', '\0<img url="http://blabla.com">', payload, re.IGNORECASE)
        del packet[TCP].chksum
        del packet[IP].chksum

        print('Injected image tag!')

        return packet