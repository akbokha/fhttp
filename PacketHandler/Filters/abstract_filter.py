from abc import ABCMeta, abstractmethod

from scapy.layers.l2 import Ether


class AbstractFilter:
    __metaclass__ = ABCMeta

    def is_filtered(self, packet):
        # type: (Ether) -> bool
        return self.to_string(packet) is not None

    @abstractmethod
    def to_string(self, packet):
        # type: (Ether) -> str or None
        pass
