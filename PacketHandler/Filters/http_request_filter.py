import re

from scapy.layers.l2 import Ether

from abstract_filter import AbstractFilter


class HttpRequestFilter(AbstractFilter):

    def is_filtered(self, packet):
        # type: (Ether) -> bool
        
        tcp = packet.getlayer("TCP")
        if tcp is not None:
            match = re.search(r"^GET [^\n]* HTTP/\d(\.\d)?[^\n]*\r\n", str(tcp.payload))
            return match is not None

        return False
