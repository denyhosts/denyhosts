from __future__ import print_function, unicode_literals

from os.path import dirname, join as ospj
from tempfile import mkdtemp
import unittest

from DenyHosts.constants import PURGE_HISTORY
from DenyHosts.counter import Counter
from DenyHosts.prefs import Prefs
from DenyHosts.purgecounter import PurgeCounter

class EmptyPurgeCounterTest(unittest.TestCase):
    """
    Tests creating a PurgeCounter object with no data file. This should:
    1) not throw an exception, and
    2) result in empty sets of hosts.

    We ensure that there's no data file by making an empty temporary
    directory for this test, and assinging that path to the appropriate
    Prefs key.
    """
    def setUp(self):
        self.prefs = Prefs()
        self.prefs._Prefs__data['WORK_DIR'] = mkdtemp()

    def test_no_data_file(self):
        purgecounter = PurgeCounter(self.prefs)
        self.assertFalse(purgecounter.get_banned_for_life())
        self.assertFalse(purgecounter.get_data())

class PurgeCounterTestThreshold0(unittest.TestCase):
    """
    Tests creating a Restricted object with a data file.
    """
    def setUp(self):
        self.prefs = Prefs()
        self.prefs._Prefs__data['WORK_DIR'] = ospj(dirname(__file__), 'data/purgecounter/static')

    def test_data_file(self):
        purgecounter = PurgeCounter(self.prefs)
        self.assertFalse(purgecounter.get_banned_for_life())
        self.assertEqual(len(purgecounter.get_data()), 1)

class PurgeCounterTestThreshold1(unittest.TestCase):
    """
    Tests creating a Restricted object with a data file.
    """
    def setUp(self):
        self.prefs = Prefs()
        self.prefs._Prefs__data['WORK_DIR'] = ospj(dirname(__file__), 'data/purgecounter/static')
        self.prefs._Prefs__data['PURGE_THRESHOLD'] = 1

    def test_data_file(self):
        purgecounter = PurgeCounter(self.prefs)
        self.assertEqual(len(purgecounter.get_banned_for_life()), 1)
        self.assertEqual(len(purgecounter.get_data()), 1)

class PurgeCounterTestWriteData(unittest.TestCase):
    """
    Tests creating a Restricted object with a data file.
    """
    def setUp(self):
        self.prefs = Prefs()
        work_dir = ospj(dirname(__file__), 'data/purgecounter/dynamic')
        self.filename = ospj(work_dir, PURGE_HISTORY)
        self.prefs._Prefs__data['WORK_DIR'] = work_dir
        self.counter = Counter()
        host = 'host'
        count = 1
        self.counter[host] += count
        self.test_string = '%s:%s\n' % (host, self.counter[host])

    def test_data_file(self):
        purgecounter = PurgeCounter(self.prefs)
        purgecounter.write_data(self.counter)

        with open(self.filename) as f:
            self.assertEqual(f.read(), self.test_string)

class PurgeCounterTestIncrement(unittest.TestCase):
    def setUp(self):
        self.prefs = Prefs()
        work_dir = mkdtemp()
        self.filename = ospj(work_dir, PURGE_HISTORY)
        self.prefs._Prefs__data['WORK_DIR'] = work_dir
        self.hosts = set(['host1', 'host2'])

    def test_increment(self):
        purge_counter = PurgeCounter(self.prefs)
        self.assertFalse(purge_counter.get_data())
        purge_counter.increment(self.hosts)
        data = purge_counter.get_data()
        self.assertEqual(set(data), self.hosts)
