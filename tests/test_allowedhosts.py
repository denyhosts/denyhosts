from __future__ import print_function, unicode_literals

from os.path import abspath, dirname, join as ospj
import unittest

from DenyHosts.allowedhosts import AllowedHosts

class AllowedHostsBase(unittest.TestCase):
    def setUp(self):
        data_dir = ospj(dirname(abspath(__file__)), 'data')
        # Initialize minimal preferences dict: just enough
        # for the AllowedHosts constructor
        prefs = {
            'WORK_DIR': data_dir,
            'ALLOWED_HOSTS_HOSTNAME_LOOKUP': 'true',
        }
        self.allowed_hosts = AllowedHosts(prefs)
        self.allowed_hosts.load_hosts()

# TODO replace with assertIn/assertNotIn when dropping support for 2.6
class AllowedHostsBasicTest(AllowedHostsBase):
    def test_positive(self):
        self.assertTrue('127.0.0.1' in self.allowed_hosts)

    def test_negatives(self):
        self.assertFalse('10.0.0.1' in self.allowed_hosts)
        self.assertFalse('127.0.0.2' in self.allowed_hosts)
        self.assertFalse('0.0.0.0' in self.allowed_hosts)
        self.assertFalse('bogus' in self.allowed_hosts)
