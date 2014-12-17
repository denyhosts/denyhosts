from __future__ import print_function, unicode_literals

from os.path import dirname, join as ospj
import unittest

from DenyHosts.deny_hosts import DenyHosts
from DenyHosts.lockfile import LockFile
from DenyHosts.prefs import Prefs

class DenyHostsBasicTest(unittest.TestCase):
    def setUp(self):
        self.directory = ospj(dirname(__file__), 'data/deny_hosts')
        self.work_dir = ospj(self.directory, 'work')
        self.logfile = ospj(self.work_dir, 'logfile')
        self.prefs = Prefs()

        self.lock_file = LockFile(ospj(self.directory, 'lockfile'))
        self.lock_file.remove(die_=False)
        self.lock_file.create()

        self.prefs._Prefs__data['ETC_DIR'] = ospj(self.directory, 'etc')
        self.prefs._Prefs__data['WORK_DIR'] = self.work_dir

    def test_init(self):
        DenyHosts(self.logfile, self.prefs, self.lock_file)

    def tearDown(self):
        self.lock_file.remove()
