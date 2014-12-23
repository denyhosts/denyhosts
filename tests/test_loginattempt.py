from __future__ import print_function, unicode_literals

from os.path import dirname, join as ospj
from tempfile import mkdtemp
import unittest

from DenyHosts.prefs import Prefs
from DenyHosts.loginattempt import LoginAttempt

class BasicLoginAttemptTest(unittest.TestCase):
    def setUp(self):
        self.allowed_hosts = ['host1', 'host2']
        self.prefs = Prefs()
        self.prefs._Prefs__data['WORK_DIR'] = mkdtemp()

        keys = [
            'DENY_THRESHOLD_INVALID',
            'DENY_THRESHOLD_VALID',
            'DENY_THRESHOLD_ROOT',
            'DENY_THRESHOLD_RESTRICTED',
        ]
        for key in keys:
            self.prefs._Prefs__data[key] = 0

    def test_no_data_file(self):
        login_attempt = LoginAttempt(self.prefs, set(self.allowed_hosts))
        self.assertFalse(login_attempt.get_abusive_hosts_invalid())
        self.assertFalse(login_attempt.get_abusive_hosts_root())
        self.assertFalse(login_attempt.get_abusive_hosts_restricted())
        self.assertFalse(login_attempt.get_abusive_hosts_valid())
        self.assertFalse(login_attempt.get_abused_users_invalid())
        self.assertFalse(login_attempt.get_abused_users_valid())
        self.assertFalse(login_attempt.get_abused_users_and_hosts())
        self.assertFalse(login_attempt.get_suspicious_logins())
