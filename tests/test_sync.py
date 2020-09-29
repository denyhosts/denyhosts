from __future__ import print_function, unicode_literals

from os.path import dirname, join as ospj
from random import randint
import unittest
import sys
if sys.version_info < (3, 0): 
    from SimpleXMLRPCServer import SimpleXMLRPCServer
    from xmlrpclib import ServerProxy
else:
    from xmlrpc.server import SimpleXMLRPCServer
    from xmlrpc.client import ServerProxy
from tempfile import mkdtemp
from threading import Lock, Thread, local as thread_local
from DenyHosts.constants import SYNC_HOSTS, SYNC_RECEIVED_HOSTS, SYNC_TIMESTAMP
from DenyHosts.prefs import Prefs
from DenyHosts.sync import Sync
from DenyHosts.sync import get_plural

LOCAL_SYNC_SERVER_ADDRESS = ('127.0.0.1', 9911)
LOCAL_SYNC_SERVER_URL = 'http://%s:%d' % LOCAL_SYNC_SERVER_ADDRESS

class MockSyncServer(object):
    def __init__(self):
        self.hosts = []

    def get_hosts(self):
        """
        Test method to directly return stored hosts
        """
        return self.hosts

    def get_new_hosts(self, timestamp, threshold, hosts_added, download_resiliency):
        """
        Matches the API inferred from the Sync class
        """
        return {
            'hosts': self.hosts,
            'timestamp': '0',
        }

    def add_hosts(self, hosts):
        self.hosts.extend(hosts)

class SyncServerTest(unittest.TestCase):
    """
    Base class of all Sync test classes that use a mock sync server.
    """
    def sync_server(self):
        self.thread_local.alive = True
        server = None
        try:
            server = SimpleXMLRPCServer(LOCAL_SYNC_SERVER_ADDRESS, allow_none=True, logRequests=False)
            server.register_function(self._exit, 'exit')
            sync_server = MockSyncServer()
            server.register_instance(sync_server)
        finally:
            self.lock.release()
        if server is not None:
            while True:
                if not self.thread_local.alive:
                    break
                server.handle_request()

    def _exit(self):
        self.thread_local.alive = False

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
        self.thread_local = thread_local()
        self.server_thread = Thread(target=self.sync_server)
        self.server_thread.start()
        self.lock.acquire()
        self.remote_sync_server = ServerProxy(LOCAL_SYNC_SERVER_URL, allow_none=True)
        self.lock.release()

    def tearDown(self):
        self.remote_sync_server.exit()
        self.server_thread.join()

class MockSyncServerTest(SyncServerTest):
    """
    Test the mock sync server itself.
    """
    def test_add_hosts(self):
        hosts = ['host1', 'host2']
        self.remote_sync_server.add_hosts(['host1', 'host2'])
        data = self.remote_sync_server.get_new_hosts(None, None, None, None)
        self.assertEqual(data['hosts'], hosts)
        self.assertEqual(self.remote_sync_server.get_hosts(), hosts)

    def test_add_no_hosts(self):
        self.remote_sync_server.add_hosts([])
        data = self.remote_sync_server.get_new_hosts(None, None, None, None)
        self.assertFalse(data['hosts'])
        self.assertFalse(self.remote_sync_server.get_hosts())

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

class SyncTestBasic(SyncServerTest):
    def setUp(self):
        super(SyncTestBasic, self).setUp()
        self.prefs = Prefs()
        self.prefs._Prefs__data['SYNC_SERVER'] = LOCAL_SYNC_SERVER_URL
        self.prefs._Prefs__data['WORK_DIR'] = ospj(dirname(__file__), 'data/sync/static')

    def test_connect_false(self):
        syncserver = self.prefs._Prefs__data['SYNC_SERVER']
        self.prefs._Prefs__data['SYNC_SERVER'] = None
        sync = Sync(self.prefs)
        self.assertFalse(sync.xmlrpc_connect())
        self.prefs._Prefs__data['SYNC_SERVER'] = syncserver

    def test_connect_disconnect(self):
        sync = Sync(self.prefs)
        self.assertTrue(sync.xmlrpc_connect())
        self.assertFalse(sync._Sync__server is None)
        self.assertTrue(sync._Sync__connected)
        sync.xmlrpc_disconnect()
        self.assertTrue(sync._Sync__server is None)
        self.assertFalse(sync._Sync__connected)


class SyncTestSendHosts(SyncServerTest):
    def setUp(self):
        super(SyncTestSendHosts, self).setUp()
        self.prefs = Prefs()
        self.prefs._Prefs__data['SYNC_SERVER'] = LOCAL_SYNC_SERVER_URL
        work_dir = mkdtemp()
        self.prefs._Prefs__data['WORK_DIR'] = work_dir

        self.test_hosts = ['host1', 'host2', 'host3']
        with open(ospj(work_dir, SYNC_HOSTS), 'w') as f:
            for host in self.test_hosts:
                print(host, file=f)

    def test_send_hosts(self):
        sync = Sync(self.prefs)
        self.assertFalse(sync._Sync__hosts_added)
        self.assertTrue(sync.send_new_hosts())
        self.assertEqual(sync._Sync__hosts_added, self.test_hosts)

class SyncTestReceiveHosts(SyncServerTest):
    def setUp(self):
        super(SyncTestReceiveHosts, self).setUp()
        self.prefs = Prefs()
        self.prefs._Prefs__data['SYNC_SERVER'] = LOCAL_SYNC_SERVER_URL
        self.work_dir = mkdtemp()
        self.prefs._Prefs__data['WORK_DIR'] = self.work_dir
        self.test_hosts = ['host1', 'host2', 'host3']
        self.remote_sync_server.add_hosts(self.test_hosts)

    def test_send_hosts(self):
        sync = Sync(self.prefs)
        self.assertEqual(sync.receive_new_hosts(), self.test_hosts)
        filename = ospj(self.work_dir, SYNC_RECEIVED_HOSTS)
        with open(filename) as f:
            hosts = [line.strip().split(':')[0] for line in f]
        self.assertEqual(self.test_hosts, hosts)

class SyncTestPlaural(unittest.TestCase):
    def test_plural_one(self):
        self.assertEqual(get_plural(['test']), '')

    def test_plural_multiple(self):
        self.assertEqual(get_plural(['test', 'two']), 's')
