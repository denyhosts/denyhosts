import os
from util import die
from regex import PREFS_REGEX


class Prefs:
    def __init__(self, path=None):
        self.__data = {'ADMIN_EMAIL': None,
                       'SUSPICIOUS_LOGIN_REPORT_ALLOWED_HOSTS': 'yes',
                       'HOSTNAME_LOOKUP': 'yes'}

        # reqd[0]: required field name
        # reqd[1]: is value required? (False = value can be blank)
        self.reqd = (('DENY_THRESHOLD', True),
                     ('SECURE_LOG', True),
                     ('LOCK_FILE', True),
                     ('BLOCK_SERVICE', False),
                     ('PURGE_DENY', False),
                     ('HOSTS_DENY', True),
                     ('WORK_DIR', True))

        self.to_int = ('DENY_THRESHOLD', )
                
        if path: self.load_settings(path)

        
    def load_settings(self, path):
        try:
            fp = open(path, "r")
        except Exception, e :
            die("Error reading file: %s" % path, e)


        for line in fp:
            line = line.strip()
            if not line or line[0] in ('\n', '#'):
                continue
            m = PREFS_REGEX.search(line)
            if m:
                name = m.group('name').upper()
                value = m.group('value')
                #print name, value
                if not value: value = None
                if name in self.to_int:
                    value = int(value)
                self.__data[name] = value
        fp.close()
        self.check_required(path)


    def check_required(self, path):
        ok = 1
        for name_reqd, val_reqd in self.reqd:
            if not self.__data.has_key(name_reqd):
                print "Missing configuration parameter: %s" % name_reqd
                ok = 0
            elif val_reqd and not self.__data[name_reqd]:
                print "Missing configuration value for: %s" % name_reqd
                ok = 0

        if not ok:
            die("You must correct these problems found in: %s" % path)


    def get(self, name):
        return self.__data[name]


    def dump(self):
        print "Preferences:"
        keys = self.__data.keys()
        for key in keys:
            print "   %s: [%s]" % (key, self.__data[key])

    
