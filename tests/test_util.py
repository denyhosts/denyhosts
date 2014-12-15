from __future__ import print_function, unicode_literals

import unittest

from DenyHosts.util import is_false, is_true, parse_host

# List of 2-tuples: line to parse, expected host
HOST_TEST_DATA = [
    ('host', 'host'),
    ('ALL:127.0.0.1', '127.0.0.1'),
    (3, ''),
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
