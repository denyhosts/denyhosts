from __future__ import print_function, unicode_literals

import unittest

class UtilsTest(unittest.TestCase):
    def test_import(self):
        try:
            import DenyHosts.util
        except ImportError as e:
            if 'ipaddr' in e.msg:
                self.fail("Regression of issue #76: Fails to import util because of 'import ipaddr'")
            else:
                raise e
