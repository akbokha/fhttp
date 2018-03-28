import re

from scapy.layers.l2 import Ether

from PacketHandler.Filters.http_200_filter import Http200Filter
from abstract_filter import AbstractFilter


class CookieFilter(AbstractFilter):

    def __init__(self):
        super(CookieFilter, self).__init__()
        self._http_filter = Http200Filter()

    def is_filtered(self, packet):
        # type: (Ether) -> bool

        if not self._http_filter.is_filtered(packet):
            return False
        
        tcp = packet.getlayer("TCP")
        if tcp is not None:
            packet.show2()
            match = re.search(r"\n\n(Cookie: .+)", str(tcp.payload))
            if match is not None:
                print('Filtered packet based on cookie, found:')
                print('\t%s' % match.group(0))
                return True

        return False
        # return super(HttpCookie, self).is_filtered(packet)
