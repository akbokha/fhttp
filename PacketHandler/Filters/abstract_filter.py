from abc import ABCMeta, abstractmethod


class AbstractFilter:
    __metaclass__ = ABCMeta

    @abstractmethod
    def is_filtered(self, packet):
        pass
