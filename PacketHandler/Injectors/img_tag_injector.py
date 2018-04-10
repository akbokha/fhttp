import re

from scapy.layers.inet import TCP
from scapy.layers.l2 import Ether

from PacketHandler.Filters.http_200_filter import Http200Filter
from PacketHandler.Injectors.abstract_injector import AbstractInjector


class ImgTagInjector(AbstractInjector):

    def __init__(self, target_ip):
        super(ImgTagInjector, self).__init__()
        self._filter = Http200Filter()
        self.target_ip = target_ip

    def inject(self, packet):
        # type: (Ether) -> Ether or None
        if not self._filter.is_filtered(packet):
            return

        payload = str(packet[TCP].payload)
        match = re.match('<body>', payload, re.IGNORECASE)
        if match is not None:
            print(match.group(0))

        new_payload = re.sub('</body>', '<img width="1" height="1" src="http://' + self.target_ip + '/a.gif"></body>',
                             payload, 1, re.IGNORECASE ^ re.MULTILINE)

        if new_payload != payload:
            print('! Injected image tag')
            return self.replace_packet_tcp_payload(packet, new_payload)
