from __future__ import print_function, unicode_literals

import unittest

from os.path import dirname, join as ospj
import DenyHosts.util as util
from DenyHosts.prefs import Prefs
from datetime import datetime

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
    ('172.16.12.51', False),
    ('192.168.0.1', False),
    ('192.168.16.2', False),
    ('10.10.10.10', False),
    ('224.2.0.45', False),
    ('225.22.62.1', False),
    ('242.125.34.43', False),
    ('169.254.0.1', False),
    ('8.8.8.8', True),
    ('4.4.2.2', True),
    ('49.88.112.60', True),
    ('216.58.206.100', True),
    ('2.19.61.200', True),
    ('11.28.51.201', True)
]

class UtilsTest(unittest.TestCase):
    def setUp(self):
        self.true_strings = ['1', 't', 'true', 'y', 'yes']
        self.false_strings = ['', 'false', 'ye', 'tr']
        self.prefs = Prefs()
        self.prefs._Prefs__data['WORK_DIR'] = ospj(dirname(__file__), 'data/utils/')
        self.prefs._Prefs__data['DAEMON_LOG'] = ospj(self.prefs.get('WORK_DIR'), 'daemon.log')
        self.prefs._Prefs__data['ADMIN_EMAIL'] = 'denyhosts@mailinator.com'
        self.prefs._Prefs__data['SMTP_FROM'] = 'travisci@mailinator.com'
        self.prefs._Prefs__data['SMTP_SUBJECT'] = 'Denyhosts Mailinator'
        self.prefs._Prefs__data['SMTP_DATE_FORMAT'] = '%Y%m%d'
        self.prefs._Prefs__data['SMTP_HOST'] = 'localhost'
        self.prefs._Prefs__data['SMTP_PORT'] = 2500
        self.prefs._Prefs__data['SMTP_SSL'] = 'False'

    def test_is_true(self):
        for string in self.true_strings:
            self.assertTrue(util.is_true(string))

        for string in self.false_strings:
            self.assertFalse(util.is_true(string))

    def test_is_false(self):
        for string in self.true_strings:
            self.assertFalse(util.is_false(string))

        for string in self.false_strings:
            self.assertTrue(util.is_false(string))

    def test_parse_host(self):
        for line, expected in HOST_TEST_DATA:
            self.assertEqual(util.parse_host(line), expected)

    def test_valid_ip(self):
        for ip, expected in TEST_IPS:
            self.assertEqual(util.is_valid_ip_address(ip), expected)

    def test_setup_logging_with_debug(self):
        self.assertIsNone(util.setup_logging(self.prefs, True, False, False))

    def test_setup_logging_no_debug(self):
        self.assertIsNone(util.setup_logging(self.prefs, False, False, False))

    def test_seconds(self):
        self.assertEqual(util.calculate_seconds(1), 1)

    def test_invalid_seconds_format(self):
        with self.assertRaises(Exception) as cm:
            util.calculate_seconds(datetime.now())
            self.assertEqual(cm.exception, 'Error')

    def test_seconds_zero_false(self):
        with self.assertRaises(Exception) as cm:
            util.calculate_seconds('0', False)
            self.assertEqual(cm.exception, 'Error')

    def test_send_email_success(self):
        self.assertIsNone(util.send_email(self.prefs, 'testing report success'))

    def test_send_email_error(self):
        self.assertIsNone(util.send_email(self.prefs, 'testing report failure'))

    def test_whitespace(self):
        self.assertEqual(
            util.normalize_whitespace('testing whitespace  for   denyhosts'),
            'testing whitespace for denyhosts'
        )

    def test_get_hostname_bug_145(self):
        self.assertEqual(
            util.gethostbyname('68.ip-51-38-131.eu'),
            '51.38.131.68'
        )
