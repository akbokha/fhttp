import unittest

from ip_to_mac_mapper import IpToMacMapper

from abc import ABCMeta

class AbstractTest(unittest.TestCase):
    __metaclass__ = ABCMeta

    def setUp(self):
        self.mockedMapping = IpToMacMapper().set_all({
            '192.168.56.101': '08:00:27:B0:A1:AB',
            '192.168.56.102': '08:00:27:C6:A4:61',
        })