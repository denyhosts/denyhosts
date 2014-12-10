from __future__ import print_function, unicode_literals

import unittest

# From Helmut Grohne's disclosure of this CVE
CVE_2013_6890_LINES = """
sshd[123]: Invalid user Invalid user root from 123.123.123.123 from 21.21.21.21
sshd[123]: input_userauth_request: invalid user Invalid user root from 123.123.123.123 [preauth]
sshd[123]: Connection closed by 21.21.21.21 [preauth]
"""

class CVEsTestCase(unittest.TestCase):
    def test_cve_2006_6301(self):
        self.assertTrue(False)

    def test_cve_2007_4323(self):
        self.assertTrue(False)

    def test_cve_2013_6890(self):
        self.assertTrue(False)
