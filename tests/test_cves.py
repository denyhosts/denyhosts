from __future__ import print_function, unicode_literals

import unittest

from DenyHosts.regex import FAILED_ENTRY_REGEX_MAP, SSHD_FORMAT_REGEX

# From Helmut Grohne's disclosure of this CVE
CVE_2013_6890_LINES = [
    ' sshd[123]: Invalid user Invalid user root from 123.123.123.123 from 21.21.21.21',
    ' sshd[123]: input_userauth_request: invalid user Invalid user root from 123.123.123.123 [preauth]',
    ' sshd[123]: Connection closed by 21.21.21.21 [preauth]',
]

CVE_2013_6890_USER = 'Invalid user root from 123.123.123.123'
CVE_2013_6890_HOST = '21.21.21.21'

class CVEsTestCase(unittest.TestCase):
    def test_cve_2006_6301(self):
        pass

    def test_cve_2007_4323(self):
        pass

    def test_cve_2013_6890(self):
        user = None
        host = None
        # There's no harm in iterating over all three lines even though
        # the first contains what we want. The second and third lines
        # don't match any of the 'failed entry' regexes.
        for line in CVE_2013_6890_LINES:
            # TODO separate matching behavior into a common function
            # that's also used by the DenyHosts daemon class
            sshd_m = SSHD_FORMAT_REGEX.match(line)
            if sshd_m:
                message = sshd_m.group('message')

                for rx in FAILED_ENTRY_REGEX_MAP.values():
                    m = rx.search(message)
                    if m:
                        user = m.group('user')
                        host = m.group('host')
        self.assertEqual(user, CVE_2013_6890_USER)
        self.assertEqual(host, CVE_2013_6890_HOST)
