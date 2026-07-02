import hashlib
import ipaddress
import unittest

from aura_suite.password_audit import ALGORITHMS
from aura_suite.network_scanner import SERVICES


class ProjectCoreTests(unittest.TestCase):
    def test_supported_hash_lengths(self):
        samples = {name: hashlib.new(name, b"example").hexdigest() for name in ALGORITHMS.values()}
        for name, digest in samples.items():
            self.assertEqual(ALGORITHMS[len(digest)], name)

    def test_scanner_services_are_unique_valid_ports(self):
        self.assertEqual(len(SERVICES), len(set(SERVICES)))
        self.assertTrue(all(1 <= port <= 65535 for port in SERVICES))

    def test_private_example_network(self):
        network = ipaddress.ip_network("192.168.1.0/24")
        self.assertTrue(network.is_private)
        self.assertEqual(network.num_addresses, 256)


if __name__ == "__main__":
    unittest.main()
