from __future__ import print_function, unicode_literals

from os.path import abspath, dirname, join as ospj
import unittest

from DenyHosts.allowedhosts import AllowedHosts

class AllowedHostsBase(unittest.TestCase):
    def setUp(self):
        data_dir = ospj(dirname(abspath(__file__)), 'data')
        allowed_hosts_filename = ospj(data_dir, 'allowedhosts.txt')
        # Initialize minimal preferences dict: just enough for the
        # AllowedHosts constructor
        prefs = {
            'WORK_DIR': data_dir,
            'ALLOWED_HOSTS_HOSTNAME_LOOKUP': 'true',
        }
        self.allowed_hosts = AllowedHosts(prefs)
        self.allowed_hosts.load_hosts()

class AllowedHostsBasicTest(AllowedHostsBase):
    def test_positive(self):
        self.assertIn('127.0.0.1', self.allowed_hosts)

    def test_negatives(self):
        self.assertNotIn('10.0.0.1', self.allowed_hosts)
        self.assertNotIn('127.0.0.2', self.allowed_hosts)
        self.assertNotIn('0.0.0.0', self.allowed_hosts)
        self.assertNotIn('bogus', self.allowed_hosts)
