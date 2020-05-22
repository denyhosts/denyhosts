from __future__ import print_function, unicode_literals

import unittest

from DenyHosts.report import Report

class ReportTest(unittest.TestCase):
    def setUp(self):
        self.report = Report(hostname_lookup='false')

    def test_empty(self):
        self.assertTrue(self.report.empty())
        self.assertEqual(self.report.get_report(), '')

    def test_add_section(self):
        self.report.add_section('message', ['line1', ('line2', 1)])
        expected_report = ('message:\n\nline1\nline2: 1\n\n\n------------------'
            '----------------------------------------------------\n')
        self.assertEqual(self.report.get_report(), expected_report)

    def test_get_hostname(self):
        self.assertEqual(self.report.get_hostname('google.com'), 'google.com')

    def test_get_hostname2(self):
        self.assertEqual(self.report.get_hostname('8.8.8.8'), '8.8.8.8 (dns.google)')

    def test_clear(self):
        self.assertIsNone(self.report.clear())
        self.assertEqual(self.report.report, '')

    def test_report_not_empty(self):
        self.report.report = 'test'
        self.assertEqual(self.report.empty(), 0)

    def test_add_section_with_hostname_lookup(self):
        self.report.hostname_lookup = True
        self.report.add_section('message', ['line1', ('line2', 1)])
        expected_report = ('message:\n\nline1\nline2: 1\n\n\n------------------'
            '----------------------------------------------------\n')
        self.assertEqual(self.report.get_report(), expected_report)
