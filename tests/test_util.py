from __future__ import print_function, unicode_literals

import unittest

from DenyHosts.util import is_false, is_true, parse_host, is_valid_ip_address

# List of 2-tuples: line to parse, expected host
HOST_TEST_DATA = [
    ('host', 'host'),
    ('ALL:127.0.0.1', '127.0.0.1'),
    (3, ''),
]

VALID_IPADDRESS_DATA = [
    '216.58.206.100',
    '2.19.61.200',
    '11.28.51.201',
    '8.8.8.8'
]

INVALID_IPADDRESS_DATA = [
    '127.0.0.1',
    '192.168.16.2',
    '10.10.10.10',
    '169.254.0.1',
    '172.16.12.51',
    '225.22.62.1',
    '242.125.34.43'
]

class UtilsTest(unittest.TestCase):
    def setUp(self):
        self.true_strings = ['1', 't', 'true', 'y', 'yes']
        self.false_strings = ['', 'false', 'ye', 'tr']

    def test_is_true(self):
        for string in self.true_strings:
            self.assertTrue(is_true(string))

        for string in self.false_strings:
            self.assertFalse(is_true(string))

    def test_is_false(self):
        for string in self.true_strings:
            self.assertFalse(is_false(string))

        for string in self.false_strings:
            self.assertTrue(is_false(string))

    def test_parse_host(self):
        for line, expected in HOST_TEST_DATA:
            self.assertEqual(parse_host(line), expected)

    def test_valid_ip_address(self):
        for ip in VALID_IPADDRESS_DATA:
            self.assertTrue(is_valid_ip_address(ip))

    def test_invalid_ip_address(self):
        for ip in INVALID_IPADDRESS_DATA:
            self.assertFalse(is_valid_ip_address(ip))
