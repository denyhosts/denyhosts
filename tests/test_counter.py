from __future__ import print_function, unicode_literals

from datetime import datetime, timedelta
import time
import unittest

from DenyHosts.counter import Counter, CounterRecord

class CounterRecordTest(unittest.TestCase):
    def test_init(self):
        c = CounterRecord()
        self.assertEqual(c.get_count(), 0)
        # Counter.__date is initialized with time.asctime(), so there isn't
        # much to test beyond the type
        self.assertTrue(isinstance(c.get_date(), str))

    def test_init_provided_date(self):
        """
        CounterRecord.__date is intended to be a string (for some reason; a datetime
        object would be more appropriate), but any object can be used. Verify that
        what we pass to the constructor is accessible.
        """
        date = object()
        c = CounterRecord(date=date)
        self.assertTrue(c.get_date() is date)

    def test_init_provided_count(self):
        """
        CounterRecord.__count is intended to be numeric, but any object can be used.
        Verify that what we pass to the constructor is accessible.
        """
        count = object()
        c = CounterRecord(count=count)
        self.assertTrue(c.get_count() is count)

    def test_str(self):
        """
        CounterRecord.__str__ is actually used in PurgeCounter.write_data, so it's
        worth testing
        """
        count = 1
        date = object()
        c = CounterRecord(count=count, date=date)
        string = '%d:%s' % (count, date)
        self.assertEqual(str(c), string)

    def test_add(self):
        """
        CounterRecord.__add__ is *horrible* design, but that's how it's been for a
        very long time. I want test coverage for the current behavior before making
        any changes.
        """
        c = CounterRecord()
        orig_date = c.get_date()
        self.assertEqual(c.get_count(), 0)
        increment = 4
        # !
        c + increment
        self.assertEqual(c.get_count(), increment)
        # Original attempt: self.assertNotEqual(c.get_date(), orig_date)
        # time.asctime only provides seconds in that string representation of the
        # date, though, so just verify that the two strings are different objects
        # since they'll usually be equal
        self.assertFalse(c.get_date() is orig_date)

    def test_reset_count(self):
        c = CounterRecord()
        c + 1
        orig_date = c.get_date()
        c.reset_count()
        self.assertEqual(c.get_count(), 0)
        self.assertTrue(c.get_date() is orig_date)

    def test_age_count_newer(self):
        """
        Initialize a CounterRecord to one hour ago, then call age_count with 2 hours
        to verify that the count won't reset. ("Reset if the stored date is older than
        2 hours ago")
        """
        one_hour_ago = datetime.now() - timedelta(hours=1)
        date_str = time.asctime(one_hour_ago.timetuple())
        count = object()
        c = CounterRecord(count=count, date=date_str)
        c.age_count(2 * 60 * 60)
        self.assertEqual(c.get_count(), count)

    def test_age_count_older(self):
        """
        Initialize a CounterRecord to one hour ago, then reset the count by passing 0
        to age_count (i.e. "reset if the stored date is older than now")
        """
        one_hour_ago = datetime.now() - timedelta(hours=1)
        date_str = time.asctime(one_hour_ago.timetuple())
        count = object()
        c = CounterRecord(count=count, date=date_str)
        c.age_count(0)
        self.assertEqual(c.get_count(), 0)

    def test_counter_repr(self):
        one_hour_ago = datetime.now() - timedelta(hours=1)
        date_str = time.asctime(one_hour_ago.timetuple())
        count = object()
        c = CounterRecord(count=count, date=date_str)
        c.age_count(0)
        self.assertEqual(c.__repr__(), 'CountRecord <{} - {}>'.format(0, date_str))

class CounterTest(unittest.TestCase):
    def test_init(self):
        c = Counter()
        self.assertEqual(len(c), 0)

    def test_missing_key(self):
        c = Counter()
        key = 'key'
        value = c[key]
        self.assertEqual(value.get_count(), 0)
        self.assertTrue(key in c)

    def test_existing_key(self):
        key = 'key'
        value = object()
        c = Counter()
        c[key] = value
        self.assertTrue(c[key] is value)
