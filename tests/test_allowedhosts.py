from __future__ import print_function, unicode_literals

from os.path import abspath, dirname, join as ospj
from tempfile import mkdtemp
import unittest

from DenyHosts.allowedhosts import AllowedHosts
from DenyHosts.constants import ALLOWED_WARNED_HOSTS
from DenyHosts.prefs import Prefs

# TODO use assertIn/assertNotIn when dropping support for 2.6

class AllowedHostsBase(unittest.TestCase):
    def setUp(self):
        data_dir = ospj(dirname(abspath(__file__)), 'data')
        self.prefs = Prefs()
        self.prefs._Prefs__data['WORK_DIR'] = data_dir
        self.prefs._Prefs__data['ALLOWED_HOSTS_HOSTNAME_LOOKUP'] = 'false'
        self.allowed_hosts = AllowedHosts(self.prefs)

class AllowedHostsBasicTest(AllowedHostsBase):
    def test_positives(self):
        self.assertTrue('127.0.0.1' in self.allowed_hosts)
        self.assertTrue('172.16.0.1' in self.allowed_hosts)

    def test_negatives(self):
        self.assertFalse('10.0.0.1' in self.allowed_hosts)
        self.assertFalse('127.0.0.2' in self.allowed_hosts)
        self.assertFalse('0.0.0.0' in self.allowed_hosts)
        self.assertFalse('bogus' in self.allowed_hosts)

class AllowedHostsWildcardTest(AllowedHostsBase):
    def test_positives(self):
        self.assertTrue('192.168.1.1' in self.allowed_hosts)
        self.assertTrue('192.168.1.255' in self.allowed_hosts)

    def test_negatives(self):
        self.assertFalse('192.168.0.1' in self.allowed_hosts)
        self.assertFalse('255.255.255.255' in self.allowed_hosts)

class AllowedHostsRangeTest(AllowedHostsBase):
    def test_positives(self):
        self.assertTrue('1.1.1.20' in self.allowed_hosts)
        self.assertTrue('1.1.1.39' in self.allowed_hosts)

    def test_negatives(self):
        self.assertFalse('1.1.1.10' in self.allowed_hosts)
        self.assertFalse('1.1.1.50' in self.allowed_hosts)

class AllowedHostsHostnameTest(AllowedHostsBase):
    def test_positives(self):
        self.assertTrue('hostname' in self.allowed_hosts)

    def test_negatives(self):
        self.assertFalse('another_hostname' in self.allowed_hosts)

class AllowedHostsWarnedHostsTest(unittest.TestCase):
    """
    Not a subclass of AllowedHostsBase since testing the warned
    hosts functionality is kind of distinct from tracking a set
    of allowed hosts
    """
    def setUp(self):
        self.work_dir = mkdtemp()
        self.warned_hosts_filename = ospj(self.work_dir, ALLOWED_WARNED_HOSTS)
        self.prefs = Prefs()
        self.prefs._Prefs__data['WORK_DIR'] = self.work_dir
        self.prefs._Prefs__data['ALLOWED_HOSTS_HOSTNAME_LOOKUP'] = 'false'
        self.allowed_hosts = AllowedHosts(self.prefs)

    def test_no_new_warned_host(self):
        self.assertFalse(self.allowed_hosts.get_new_warned_hosts())

    def test_no_warned_host(self):
        self.allowed_hosts.load_warned_hosts()
        self.assertFalse(self.allowed_hosts.get_new_warned_hosts())

    def test_load_warned_hosts(self):
        hosts = ['host1', 'host2']
        with open(self.warned_hosts_filename, 'w') as f:
            for host in hosts:
                print(host, file=f)

        self.allowed_hosts.load_warned_hosts()
        self.assertEqual(set(hosts), set(self.allowed_hosts.warned_hosts))

    def test_save_warned_hosts(self):
        hosts = ['host1', 'host2']
        test_string = ''.join(host + '\n' for host in hosts)

        for host in hosts:
            self.allowed_hosts.add_warned_host(host)
        self.allowed_hosts.save_warned_hosts()

        with open(self.warned_hosts_filename) as f:
            self.assertEqual(test_string, f.read())
