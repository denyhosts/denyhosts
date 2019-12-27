from __future__ import print_function, unicode_literals

import unittest

from DenyHosts.util import is_false, is_true, parse_host, is_valid_ip_address

# List of 2-tuples: line to parse, expected host
HOST_TEST_DATA = [
    ('host', 'host'),
    ('ALL:127.0.0.1', '127.0.0.1'),
    (3, ''),
]

TEST_IPS = [
    ('127.0.0.1', False),
    ('127.0.1.1', False),
    ('10.5.0.234', False),
    ('172.16.0.1', False),
    ('192.168.0.1', False),
    ('224.2.0.45', False),
    ('8.8.8.8', True),
    ('4.4.2.2', True),
    ('49.88.112.60', True)
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

    def test_valid_ip(self):
        for ip, expected in TEST_IPS:
            self.assertEqual(is_valid_ip_address(ip), expected)
