from abc import ABCMeta, abstractmethod


class PacketObserver:
    """
    An abstract implementation of the packet observer
    """
    __metaclass__ = ABCMeta

    @abstractmethod
    def update(self, handler):
        """
        :param PacketHandler handler:
        :return:
        """
        pass
