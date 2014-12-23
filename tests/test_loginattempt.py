from __future__ import print_function, unicode_literals

from os.path import dirname, join as ospj
from tempfile import mkdtemp
import unittest

from DenyHosts.prefs import Prefs
from DenyHosts.loginattempt import LoginAttempt
from DenyHosts.constants import (
    ABUSIVE_HOSTS_INVALID,
    ABUSIVE_HOSTS_ROOT,
    ABUSIVE_HOSTS_RESTRICTED,
    ABUSIVE_HOSTS_VALID,
    ABUSED_USERS_INVALID,
    ABUSED_USERS_VALID,
    ABUSED_USERS_AND_HOSTS,
    SUSPICIOUS_LOGINS,
)

# List of 2-tuples:
# [0] filename in which data is stored
# [1] LoginAttempt attribute name that reads from this file
LOGIN_ATTEMPT_ATTRIBUTE_FILENAMES = [
    (ABUSIVE_HOSTS_INVALID, 'get_abusive_hosts_invalid'),
    (ABUSIVE_HOSTS_ROOT, 'get_abusive_hosts_root'),
    (ABUSIVE_HOSTS_RESTRICTED, 'get_abusive_hosts_restricted'),
    (ABUSIVE_HOSTS_VALID, 'get_abusive_hosts_valid'),
    (ABUSED_USERS_INVALID, 'get_abused_users_invalid'),
    (ABUSED_USERS_VALID, 'get_abused_users_valid'),
    (ABUSED_USERS_AND_HOSTS, 'get_abused_users_and_hosts'),
    (SUSPICIOUS_LOGINS, 'get_suspicious_logins'),
]

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
        for filename, method_name in LOGIN_ATTEMPT_ATTRIBUTE_FILENAMES:
            self.assertFalse(getattr(login_attempt, method_name)())
