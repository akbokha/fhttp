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

        payload = str(packet[TCP].payload)
        match = re.match('<body>', payload, re.IGNORECASE)
        if match is not None:
            print(match.group(0))

        new_payload = re.sub('<body>', '<body><img scr="http://192.168.56.104/favicon.ico">', payload, 1,
                             re.IGNORECASE ^ re.MULTILINE)

        if new_payload != payload:
            print('! Injected image tag')
            return self.replace_packet_tcp_payload(packet, new_payload)
