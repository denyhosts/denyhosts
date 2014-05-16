
import time
import logging

debug = logging.getLogger("counter").debug

class CounterRecord:
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
        cutoff = long(time.time()) - age
        epoch = time.mktime(time.strptime(self.__date))
        #debug("cutoff : %d", cutoff)
        #debug("epoch  : %d", epoch)
        if cutoff > epoch:
            self.__count = 0
        

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
        except:
            count_rec = CounterRecord(0)
            #debug("%s - %s", k, count_rec)
            self.__setitem__(k, count_rec)
            #debug("dict: %s", dict.values(self))
            #debug("count_rec: %s", count_rec)
            return count_rec


        
