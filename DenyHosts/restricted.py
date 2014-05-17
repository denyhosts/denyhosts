import os

from constants import RESTRICTED_USERNAMES
try:
    set = set
except:
    from sets import Set
    set = Set
    
class Restricted:
    def __init__(self, prefs):
        self.filename = os.path.join(prefs['ETC_DIR'], RESTRICTED_USERNAMES)
        self.__data = set()
        self.load_restricted()
        
    def load_restricted(self):
        try:
            fp = open(self.filename, "r")
            for line in fp:
                line = line.strip()
                if not line: continue
                if line[0] == '#': continue
                self.__data.add(line)
        except:
            pass

    def get_restricted(self):
        return self.__data
