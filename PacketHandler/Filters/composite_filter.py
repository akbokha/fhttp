from abstract_filter import AbstractFilter


class CompositeFilter(AbstractFilter):
    def __init__(self):
        self.filters = []

    def is_filtered(self, packet):
        """
        :param packet: Ether
        :return boolean:
        """
        for f in self.filters:
            if f.is_filtered(packet):
                return True

        return False

    def attach(self, f):
        """
        :param CompositeFilter f:
        :return:
        """
        self.filters.append(f)

    def detach(self, f):
        if f in self.filters:
            self.filters.remove(f)

    def to_string(self, packet):
        result = []
        for f in self.filters:
            s = f.to_string(packet)
            if s is not None:
                result.append(type(f).__name__ + " " + s)

        if result:
            return '\n'.join(result)
        else:
            return
