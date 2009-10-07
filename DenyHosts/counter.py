
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
            self.__setitem__(k, 0)
            return 0
