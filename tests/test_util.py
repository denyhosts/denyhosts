from __future__ import print_function, unicode_literals

import os
import sys
import unittest

from DenyHosts.mail_command import send_mail_by_command
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

    def test_main_command(self):
        executable = str(sys.executable).replace(os.sep, '/')  # To support windows
        self.assertEqual(0, send_mail_by_command(executable, ["--version"], "", print))
        self.assertNotEquals(0, send_mail_by_command(executable, ["--option-that-doesnot-exist"], "", print))
        self.assertEquals(42, send_mail_by_command(executable + ' -c "import sys; c = sys.stdin.read(); exit(int(c))"',
                                                   [], '42', print))
        self.assertEquals(3, send_mail_by_command(executable + ' -c "import sys; c = sys.argv[3]; exit(int(c))"',
                                                   ["1", "2", "3"],
                                                   "spam", print))
