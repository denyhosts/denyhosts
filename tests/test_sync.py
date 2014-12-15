from __future__ import print_function, unicode_literals

from DenyHosts.prefs import Prefs
from DenyHosts.sync import Sync

import unittest

class SyncTest(unittest.TestCase):
    def setUp(self):
        self.prefs = Prefs()
        self.prefs._Prefs__data['WORK_DIR'] = 'data'
        self.sync = Sync(self.prefs)

    def test_get_sync_timestamp(self):
        timestamp = 427850432
        self.assertEqual(self.sync.get_sync_timestamp(), timestamp)
