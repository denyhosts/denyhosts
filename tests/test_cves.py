from __future__ import print_function, unicode_literals

import unittest

from DenyHosts.regex import FAILED_ENTRY_REGEX_MAP, SSHD_FORMAT_REGEX

# From https://bugs.gentoo.org/show_bug.cgi?id=157163
CVE_2006_6301_LINE = ' sshd[23964]: Invalid user foo from 123.123.123.123 from 127.0.0.1'
CVE_2006_6301_USER = 'foo from 123.123.123.123'
CVE_2006_6301_HOST = '127.0.0.1'

# From https://bugzilla.redhat.com/show_bug.cgi?id=237449
CVE_2007_5715_LINE = ' sshd[29961]: User root from 122.36.2.10 not allowed because not listed in AllowUsers'
CVE_2007_5715_USER = 'root'
CVE_2007_5715_HOST = '122.36.2.10'

# From Helmut Grohne's disclosure of this CVE
CVE_2013_6890_LINES = [
    ' sshd[123]: Invalid user Invalid user root from 123.123.123.123 from 21.21.21.21',
    ' sshd[123]: input_userauth_request: invalid user Invalid user root from 123.123.123.123 [preauth]',
    ' sshd[123]: Connection closed by 21.21.21.21 [preauth]',
]

CVE_2013_6890_USER = 'Invalid user root from 123.123.123.123'
CVE_2013_6890_HOST = '21.21.21.21'

# TODO separate matching behavior into a common function
# that's also used by the DenyHosts daemon class, instead of
# doing it ourselves in every test case here

class CVEsTestCase(unittest.TestCase):
    def test_cve_2006_6301(self):
        user = None
        host = None
        sshd_m = SSHD_FORMAT_REGEX.match(CVE_2006_6301_LINE)
        if sshd_m:
            message = sshd_m.group('message')

            for rx in FAILED_ENTRY_REGEX_MAP.values():
                m = rx.search(message)
                if m:
                    user = m.group('user')
                    host = m.group('host')
        self.assertEqual(user, CVE_2006_6301_USER)
        self.assertEqual(host, CVE_2006_6301_HOST)

    def test_cve_2007_4323(self):
        pass

    def test_cve_2007_5715(self):
        user = None
        host = None
        sshd_m = SSHD_FORMAT_REGEX.match(CVE_2007_5715_LINE)
        if sshd_m:
            message = sshd_m.group('message')

            for rx in FAILED_ENTRY_REGEX_MAP.values():
                m = rx.search(message)
                if m:
                    user = m.group('user')
                    host = m.group('host')
        self.assertEqual(user, CVE_2007_5715_USER)
        self.assertEqual(host, CVE_2007_5715_HOST)

    def test_cve_2013_6890(self):
        user = None
        host = None
        # There's no harm in iterating over all three lines even though
        # the first contains what we want. 
        for line in CVE_2013_6890_LINES:
            sshd_m = SSHD_FORMAT_REGEX.match(line)
            if sshd_m:
                message = sshd_m.group('message')

                for rx in FAILED_ENTRY_REGEX_MAP.values():
                    m = rx.search(message)
                    if m:
                        try:
                            user = m.group('user')
                            host = m.group('host')
                        except IndexError:
                            continue
                        self.assertEqual(user, CVE_2013_6890_USER)
                        self.assertEqual(host, CVE_2013_6890_HOST)
