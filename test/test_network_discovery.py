import unittest
from network_discoverer import NetworkDiscoverer
from test.abstract_test import AbstractTest


class TestNetworkDiscovery(AbstractTest):

    def test_network_discoverer(self):
        expected_mapping = self.mockedMapping.get_all()
        real_mapping = NetworkDiscoverer().get_ip_to_mac_mapping(True).get_all()

        # Ensure that every ip-mac combination we expected is also in the real data.
        for expected_ip in expected_mapping:
            self.assertIn(expected_ip, real_mapping)
            self.assertEqual(expected_mapping[expected_ip], real_mapping[expected_ip])

if __name__ == '__main__':
    unittest.main()