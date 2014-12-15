from __future__ import print_function, unicode_literals

from DenyHosts.util import is_false, is_true

import unittest

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
