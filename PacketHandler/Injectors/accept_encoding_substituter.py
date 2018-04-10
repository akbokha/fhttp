import re

from scapy.layers.inet import TCP
from scapy.layers.l2 import Ether

from PacketHandler.Filters.http_request_filter import HttpRequestFilter
from PacketHandler.Injectors.abstract_injector import AbstractInjector


class AcceptEncodingSubstituter(AbstractInjector):
    no_compression_string = "identity"

    def __init__(self, replacement=no_compression_string):
        super(AcceptEncodingSubstituter, self).__init__()
        self._replacement = replacement
        self._filter = HttpRequestFilter()

    def inject(self, packet):
        # type: (Ether) -> Ether or None
        if not self._filter.is_filtered(packet):
            return

        payload = str(packet[TCP].payload)
        new_payload = re.sub('Accept-Encoding: [^(\r\n)]*', self._replacement, payload, 1, re.IGNORECASE)

        if payload != new_payload:
            print('! Substituted Accept-Encoding header')
            return self.replace_packet_tcp_payload(packet, new_payload)
