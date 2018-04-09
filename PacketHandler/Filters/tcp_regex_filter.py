import re

from PacketHandler.Filters.abstract_filter import AbstractFilter


class TcpRegexFilter(AbstractFilter):

    def __init__(self, query, group=0):
        self._query = query
        self._group = group

    def to_string(self, packet):
        tcp = packet.getlayer("TCP")
        if tcp is not None:
            match = re.search(self._query, str(tcp.payload))

            if match is not None:
                return match.group(self._group)

        return
