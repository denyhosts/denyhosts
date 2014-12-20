from __future__ import print_function, unicode_literals

from os.path import dirname, join as ospj
from random import randint
import unittest
from SimpleXMLRPCServer import SimpleXMLRPCServer
from threading import Lock, Thread
import xmlrpclib

from DenyHosts.constants import SYNC_TIMESTAMP
from DenyHosts.prefs import Prefs
from DenyHosts.sync import Sync

class MockSyncServer(object):
    def __init__(self):
        self.hosts = []

    def get_new_hosts(self, timestamp, threshold, hosts_added, download_resiliency):
        return self.hosts

    def add_hosts(self, hosts):
        self.hosts.extend(hosts)

class SyncServerTest(unittest.TestCase):
    """
    Base class of all Sync test classes that use a mock sync server.
    """
    def sync_server(self):
        server = None
        try:
            server = SimpleXMLRPCServer(('127.0.0.1', 9911), allow_none=True, logRequests=False)
            sync_server = MockSyncServer()
            server.register_instance(sync_server)
        finally:
            self.lock.release()
        if server is not None:
            server.serve_forever()

    def setUp(self):
        # Poor-man's version of a threading.Barrier (which was added in 3.2). Make a
        # new threading.Lock and immediately acquire it. Spawn the sync_server thread,
        # then acquire the lock again. The second acquire() call will block until the
        # sync server thread is initialized -- it calls release() before entering the
        # serve_forever loop. This isn't totally free of race conditions -- a test
        # method could conceivably be run between sync_server's calls to
        # self.lock.release() and server.serve_forever. We just need our test runs
        # to behave as deterministically as possible, so hopefully this is good
        # enough for now.
        # TODO: use a real threading.Barrier when we drop support for Python 2
        self.lock = Lock()
        self.lock.acquire()
        self.server_thread = Thread(target=self.sync_server)
        self.server_thread.daemon = True
        self.server_thread.start()
        self.lock.acquire()
        self.remote_sync_server = xmlrpclib.ServerProxy('http://127.0.0.1:9911', allow_none=True)
        self.lock.release()

    def tearDown(self):
        # TODO kill server when done with test, otherwise we'll keep
        # listening on this port and further tests will fail.
        # Can't use SimpleXMLRPCServer.serve_forever with this requirement
        pass

class MockSyncServerTest(SyncServerTest):
    def test_add_hosts(self):
        hosts = ['host1', 'host2']
        self.remote_sync_server.add_hosts(['host1', 'host2'])
        self.assertEqual(self.remote_sync_server.get_new_hosts(None, None, None, None), hosts)

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

class SyncTestSendHosts(SyncServerTest):
    pass
