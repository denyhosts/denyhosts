from os.path import dirname, join as ospj
from os import remove
import unittest
import shutil
import filecmp
from DenyHosts.denyfileutil import Migrate
from DenyHosts.constants import DENY_DELIMITER

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch


class DenyHostsMigrateTest(unittest.TestCase):
    def setUp(self):
        self.directory = ospj(dirname(__file__), 'data/migrate')
        self.template = ospj(self.directory, 'hosts.deny.template')
        self.backup = ospj(self.directory, 'hosts.deny.migrate.bak')
        self.deny_file = "%s/%s" % (self.directory, 'hosts.deny')
        shutil.copy(self.template, self.deny_file)

    @patch('DenyHosts.denyfileutil.get_user_input', return_value='Yes')
    def test_migrate(self, input):
        """
        Check if Migrate creates a backup file and verify that DENY_DELIMITER
        has been written to the deny file.
        """
        Migrate(self.deny_file)
        self.assertTrue(filecmp.cmp(self.template, self.backup))
        self.assertTrue(DENY_DELIMITER in open(self.deny_file).read())

    def tearDown(self):
        remove(self.deny_file)
        remove(self.backup)
