from __future__ import print_function, unicode_literals

import unittest
from os.path import dirname, join as ospj
from os import close
import sys
import re

from DenyHosts.lockfile import LockFile


class LockFileTest(unittest.TestCase):
    def setUp(self):
        self.DIRECTORY = ospj(dirname(__file__), 'data/lockdir')
        self.LOCKPATH = ospj(self.DIRECTORY, 'lockfile')
        pass

    def test_01_check_lockfile_not_exists(self):
        lf = LockFile(self.LOCKPATH)
        self.assertFalse(lf.exists())

    def test_02_check_lockfile_create(self):
        lf = LockFile(self.LOCKPATH)
        self.assertIsNone(lf.create())
        close(lf.fd)

    def test_03_check_lockfile_exists(self):
        lf = LockFile(self.LOCKPATH)
        self.assertTrue(lf.exists())

    def test_04_check_pid(self):
        lf = LockFile(self.LOCKPATH)
        pid = lf.get_pid()
        if sys.version_info <= (3, 0):
            # py2.x coverage
            regex_match = re.match(r'[0-9]+$', pid)
            self.assertIsNotNone(regex_match)
        else:
            self.assertRegex(pid, r'^[0-9]+$')

    def test_05_check_lockfile_create_exists(self):
        lf = LockFile(self.LOCKPATH)
        with self.assertRaises(SystemExit) as cm:
            lf.create()
            self.assertEqual(cm.exception, 'Error')

    def test_06_check_lockfile_removal(self):
        lf = LockFile(self.LOCKPATH)
        self.assertIsNone(lf.remove())

    def test_07_check_lockfile_removal_not_exists(self):
        lf = LockFile(self.LOCKPATH)
        with self.assertRaises(SystemExit) as cm:
            lf.remove()
            self.assertEqual(cm.exception, 'Error')

    def test_08_get_pid_empty(self):
        lf = LockFile(self.LOCKPATH)
        self.assertEqual(lf.get_pid(), '')

    def test_09_create_remove(self):
        lf = LockFile(self.LOCKPATH)
        self.assertIsNone(lf.create())
        self.assertIsNone(lf.remove())
