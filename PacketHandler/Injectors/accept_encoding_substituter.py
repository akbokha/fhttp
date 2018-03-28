from scapy.layers.inet import TCP, IP
from scapy.layers.l2 import Ether

from PacketHandler.Filters.http_request_filter import HttpRequestFilter
from PacketHandler.Injectors.abstract_injector import AbstractInjector
import re

class AcceptEncodingSubstituter(AbstractInjector):
    def __init__(self, replacement="Accept-Encoding: identity"):
        super(AcceptEncodingSubstituter, self).__init__()
        self._replacement = replacement
        self._filter = HttpRequestFilter()

    def inject(self, packet):
        # type: (Ether) -> Ether or None
        if not self._filter.is_filtered(packet):
            return

        payload = str(packet[TCP].payload)
        new_payload = re.sub('Accept-Encoding: [^(\r\n)]*', self._replacement, payload, 1, re.IGNORECASE)
        del packet[TCP].chksum
        del packet[IP].chksum
        del packet[IP].len
        packet[TCP].remove_payload()
        packet[TCP].add_payload(payload)
        packet[TCP].build()

        if payload != new_payload:
            print('! Substituted Accept-Encoding header')
            return packet.clone_with(new_payload)
