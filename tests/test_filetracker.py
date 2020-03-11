from __future__ import print_function, unicode_literals

import unittest
from os.path import dirname, join as ospj

from DenyHosts.filetracker import FileTracker
from DenyHosts.deny_hosts import DenyHosts
from DenyHosts.lockfile import LockFile
from DenyHosts.prefs import Prefs
from DenyHosts.constants import SECURE_LOG_OFFSET


class FileTrackerTest(unittest.TestCase):
    def setUp(self):
        self.DIRECTORY = ospj(dirname(__file__), 'data/filetracker')
        self.WORK_DIR = ospj(self.DIRECTORY, 'work')
        self.LOG_FILE = ospj(self.DIRECTORY, 'logfile')
        self.SECURE_LOG_FILE = SECURE_LOG_OFFSET

    def test_01_check_offset(self):
        ft = FileTracker(self.WORK_DIR, self.LOG_FILE)
        self.assertEqual(ft.get_offset(), 70)

    def test_02_update_offset(self):
        ft = FileTracker(self.WORK_DIR, self.LOG_FILE)
        self.assertIsNone(ft.save_offset(143))

    def write_new_entry(self):
        with open(ospj(self.WORK_DIR, self.LOG_FILE), 'a') as fh:
            fh.write('\nMar  11 07:39:50 bastion sshd[29111]: Set /proc/self/oom_score_adj to 0')

    def test_03_validate_offset_after_new_entry(self):
        self.write_new_entry()
        ft = FileTracker(self.WORK_DIR, self.LOG_FILE)
        self.assertEqual(ft.get_offset(), 143)

    def write_new_file(self):
        with open(ospj(self.WORK_DIR, self.LOG_FILE), 'w') as fh:
            fh.write('Mar  12 07:39:50 bastion sshd[29111]: Set /proc/self/oom_score_adj to 0')

    def setup_denyhosts(self):
        self.prefs = Prefs()

        self.lock_file = LockFile(ospj(self.DIRECTORY, 'lockfile'))
        self.lock_file.remove(die_=False)
        self.lock_file.create()

        self.prefs._Prefs__data['ETC_DIR'] = ospj(self.DIRECTORY, 'etc')
        self.prefs._Prefs__data['WORK_DIR'] = self.WORK_DIR
        self.prefs._Prefs__data['HOSTS_DENY'] = ospj(self.prefs._Prefs__data['ETC_DIR'], 'hosts.deny')
        self.prefs._Prefs__data['DENY_THRESHOLD_INVALID'] = 5
        self.prefs._Prefs__data['DENY_THRESHOLD_VALID'] = 5
        self.prefs._Prefs__data['DENY_THRESHOLD_ROOT'] = 0
        self.prefs._Prefs__data['DENY_THRESHOLD_RESTRICTED'] = 5

    def test_04_file_rotated(self):
        ft = FileTracker(self.WORK_DIR, self.LOG_FILE)
        self.write_new_file()
        self.assertIsNone(ft.update_first_line())
        self.assertEqual(ft.get_offset(), 0)
        self.setup_denyhosts()
        new_offset = DenyHosts(self.LOG_FILE, self.prefs, self.lock_file).process_log(self.LOG_FILE, ft.get_offset())
        self.assertIsNone(ft.save_offset(new_offset))
        self.assertEqual(ft.get_offset(), new_offset)
        self.lock_file.remove()

    def clear_offset_file(self):
        with open(ospj(self.WORK_DIR, self.SECURE_LOG_FILE), 'w') as fh:
            fh.write('')

    def test_05_bug_99(self):
        self.clear_offset_file()
        ft = FileTracker(self.WORK_DIR, self.LOG_FILE)
        self.assertEqual(ft.get_offset(), 0)
