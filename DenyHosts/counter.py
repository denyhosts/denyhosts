import logging
import time

debug = logging.getLogger("counter").debug


# TODO define __eq__ for this class
class CounterRecord(object):
    def __init__(self, count=0, date=None):
        self.__count = count
        if not date:
            self.__date = time.asctime()
        else:
            self.__date = date

    def __str__(self):
        return "%d:%s" % (self.__count, self.__date)

    def __repr__(self):
        return "CountRecord <%d - %s>" % (self.__count, self.__date)

    def __add__(self, increment):
        # AAAAH!
        # Expressions like `a + 4` are usually assumed to not have any side effects,
        # but this is not the case with CounterRecord objects. With `c = CounterRecord()`,
        # simply evaluating `c + 1` will increment c.__count by 1. This is horrifying.
        self.__count += increment
        self.__date = time.asctime()
        return self

    def get_count(self):
        return self.__count

    def get_date(self):
        return self.__date

    def reset_count(self):
        self.__count = 0

    def age_count(self, age):
        cutoff = int(time.time()) - age
        epoch = time.mktime(time.strptime(self.__date))
        # debug("cutoff : %d", cutoff)
        # debug("epoch  : %d", epoch)
        if cutoff > epoch:
            self.__count = 0


# TODO replace this with collections.defaultdict
class Counter(dict):
    """
     Behaves like a dictionary, except that if the key isn't found, 0 is returned
     rather than an exception.  This is suitable for situations like:
         c = Counter()
         c['x'] += 1
    """
    def __init__(self):
        dict.__init__(self)

    def __getitem__(self, k):
        try:
            return dict.__getitem__(self, k)
        except KeyError:
            count_rec = CounterRecord(0)
            # debug("%s - %s", k, count_rec)
            self.__setitem__(k, count_rec)
            # debug("dict: %s", dict.values(self))
            # debug("count_rec: %s", count_rec)
            return count_rec
