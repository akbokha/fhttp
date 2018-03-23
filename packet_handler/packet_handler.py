from scapy.layers.l2 import Ether


class PacketHandler:
    def __init__(self):
        self.observers = []
        self.packet = None

    def attach(self, o):
        self.observers.append(o)

    def detach(self, o):
        self.observers.remove(o)

    def notify(self, packet):
        """
        :param Ether packet:
        :return:
        """
        self.packet = packet

        for o in self.observers:
            o.update(self)

    def get_packet(self):
        """
        :return Ether The supplied packet:
        """
        if self.packet is None:
            raise RuntimeError('Cannot retrieve state before first notify is called')

        return self.packet

    def set_packet(self, packet):
        """
        :param Ether packet:
        :return:
        """
        self.packet = packet
