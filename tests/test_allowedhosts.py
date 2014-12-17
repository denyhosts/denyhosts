from __future__ import print_function, unicode_literals

from os.path import abspath, dirname, join as ospj
import unittest

from DenyHosts.allowedhosts import AllowedHosts

# TODO use assertIn/assertNotIn when dropping support for 2.6

class AllowedHostsBase(unittest.TestCase):
    def setUp(self):
        data_dir = ospj(dirname(abspath(__file__)), 'data')
        # Initialize minimal preferences dict: just enough
        # for the AllowedHosts constructor
        prefs = {
            'WORK_DIR': data_dir,
            'ALLOWED_HOSTS_HOSTNAME_LOOKUP': 'false',
        }
        self.allowed_hosts = AllowedHosts(prefs)

class AllowedHostsBasicTest(AllowedHostsBase):
    def test_positive(self):
        self.assertTrue('127.0.0.1' in self.allowed_hosts)
        self.assertTrue('172.16.0.1' in self.allowed_hosts)

    def test_negatives(self):
        self.assertFalse('10.0.0.1' in self.allowed_hosts)
        self.assertFalse('127.0.0.2' in self.allowed_hosts)
        self.assertFalse('0.0.0.0' in self.allowed_hosts)
        self.assertFalse('bogus' in self.allowed_hosts)

class AllowedHostsWildcardTest(AllowedHostsBase):
    def test_positive(self):
        self.assertTrue('192.168.1.1' in self.allowed_hosts)
        self.assertTrue('192.168.1.255' in self.allowed_hosts)

    def test_negatives(self):
        self.assertFalse('192.168.0.1' in self.allowed_hosts)
        self.assertFalse('255.255.255.255' in self.allowed_hosts)

class AllowedHostsRangeTest(AllowedHostsBase):
    def test_positive(self):
        self.assertTrue('1.1.1.20' in self.allowed_hosts)
        self.assertTrue('1.1.1.39' in self.allowed_hosts)

    def test_negatives(self):
        self.assertFalse('1.1.1.10' in self.allowed_hosts)
        self.assertFalse('1.1.1.50' in self.allowed_hosts)
