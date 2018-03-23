from abc import ABCMeta, abstractmethod

from scapy.layers.l2 import Ether


class AbstractInjector:
    __metaclass__ = ABCMeta

    @abstractmethod
    def inject(self, packet):
        # type: (Ether) -> Ether
        pass
