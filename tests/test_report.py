from __future__ import print_function, unicode_literals

import unittest

from DenyHosts.report import Report

class ReportTest(unittest.TestCase):
    def test_empty(self):
        report = Report(hostname_lookup='false')
        self.assertTrue(report.empty())
        self.assertEqual(report.get_report(), '')

    def test_add_section(self):
        report = Report(hostname_lookup='false')
        report.add_section('message', ['line1', ('line2', 1)])
        expected_report = ('message:\n\nline1\nline2: 1\n\n\n------------------'
            '----------------------------------------------------\n')
        self.assertEqual(report.get_report(), expected_report)
