import re

from scapy.layers.l2 import Ether

from abstract_filter import AbstractFilter


class Http200Filter(AbstractFilter):

    def is_filtered(self, packet):
        # type: (Ether) -> bool
        
        # @todo Filters in a more refined manner, by also explicitely checking that it is HTTP traffic.
        # https://stackoverflow.com/questions/27551367/http-get-packet-sniffer-in-scapy#27566057
        tcp = packet.getlayer("TCP")
        if tcp is not None:
            match = re.search(r"^HTTP/\d(\.\d)? 200 OK[^\n]*\r\n", str(tcp.payload))
            return match is not None

        return False
