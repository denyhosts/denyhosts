from __future__ import print_function, unicode_literals

from os.path import dirname, join as ospj
from random import randint

from DenyHosts.constants import SYNC_TIMESTAMP
from DenyHosts.prefs import Prefs
from DenyHosts.sync import Sync

import unittest

class SyncTestStaticTimestamp(unittest.TestCase):
    """
    Tests that we can read the sync timestamp from the filesystem.
    """
    def setUp(self):
        self.prefs = Prefs()
        self.prefs._Prefs__data['WORK_DIR'] = ospj(dirname(__file__), 'data/sync/static')
        self.sync = Sync(self.prefs)

    def test_get_sync_timestamp(self):
        timestamp = 427850432
        self.assertEqual(self.sync.get_sync_timestamp(), timestamp)

class SyncTestDynamicTimestamp(unittest.TestCase):
    """
    Tests that we can set the timestamp on the filesystem. Separated
    into a different test class to avoid clobbering the static test data
    for SyncTestStaticTimestamp.
    """
    def setUp(self):
        self.prefs = Prefs()
        self.prefs._Prefs__data['WORK_DIR'] = ospj(dirname(__file__), 'data/sync/dynamic')
        self.sync = Sync(self.prefs)
        self.value = randint(0, 1e9)

    def test_set_sync_timestamp(self):
        self.sync.set_sync_timestamp(str(self.value))
        path = ospj(self.prefs._Prefs__data['WORK_DIR'], SYNC_TIMESTAMP)
        with open(path) as f:
            saved_timestamp = int(f.read().strip())
        self.assertEqual(self.value, saved_timestamp)
