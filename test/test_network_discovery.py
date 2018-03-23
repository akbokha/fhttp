import unittest
from network_discoverer import NetworkDiscoverer
from test.abstract_test import AbstractTest


class TestNetworkDiscovery(AbstractTest):

    def test_get_ip_to_mac_mapping(self):
        expected_mapping = self.mockedMapping.get_all()
        real_mapping = NetworkDiscoverer().get_ip_to_mac_mapping(True).get_all()

        # Ensure that every ip-mac combination we expected is also in the real data.
        for expected_ip in expected_mapping:
            self.assertIn(expected_ip, real_mapping)
            self.assertEqual(expected_mapping[expected_ip], real_mapping[expected_ip])

    def test_get_own_mac_address(self):
        self.assertEqual('08:00:27:32:f4:6a', NetworkDiscoverer().get_own_mac_address(True))

    def test_get_own_ip_address(self):
        self.assertEqual('192.168.56.103', NetworkDiscoverer().get_own_ip_address(True))


if __name__ == '__main__':
    unittest.main()