import re

from abstract_filter import AbstractFilter


class HttpCookie(AbstractFilter):

    def is_filtered(self, packet):
        """
        :param Ether packet:
        :return:
        """

        # @todo Filters in a more refined manner, by also explicitely checking that it is HTTP traffic.
        # https://stackoverflow.com/questions/27551367/http-get-packet-sniffer-in-scapy#27566057
        tcp = packet.getlayer("TCP")
        if tcp is not None:
            match = re.search(r"Cookie: (.+)", str(tcp.payload))
            if match:
                print('Filtered packet based on cookie')
                return True

        return False
        # return super(HttpCookie, self).is_filtered(packet)
