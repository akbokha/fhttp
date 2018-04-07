from abc import ABCMeta, abstractmethod

from scapy.layers.l2 import Ether


class AbstractFilter:
    __metaclass__ = ABCMeta

    def is_filtered(self, packet):
        # type: (Ether) -> bool
        """
        Decides if a packet is filtered or not
        :param Ether packet:
        :return bool: A boolean
        """
        return self.to_string(packet) is not None

    @abstractmethod
    def to_string(self, packet):
        # type: (Ether) -> str or None
        """
        :param packet: The packet to be filtered.
        :return: None when the packet is not filtered, or a string containing the relevant filtered part of the packet.
        """
        pass
