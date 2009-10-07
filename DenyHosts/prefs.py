import os
from util import die
from regex import PREFS_REGEX
import logging

debug = logging.getLogger("prefs").debug
info = logging.getLogger("prefs").info

class Prefs:
    def __init__(self, path=None):
        # default values for some of the configurable items
        self.__data = {'ADMIN_EMAIL': None,
                       'SUSPICIOUS_LOGIN_REPORT_ALLOWED_HOSTS': 'yes',
                       'HOSTNAME_LOOKUP': 'yes',
                       'DAEMON_LOG': '/var/log/denyhosts',
                       'DAEMON_SLEEP': '30s',
                       'DAEMON_PURGE': '1h',                       
                       'DAEMON_LOG_TIME_FORMAT': None,
                       'SSHD_FORMAT_REGEX': None,
                       'FAILED_ENTRY_REGEX': None,
                       'FAILED_ENTRY_REGEX2': None,
                       'FAILED_ENTRY_REGEX3': None,
                       'FAILED_ENTRY_REGEX4': None,
                       'SUCCESSFUL_ENTRY_REGEX': None,
                       'ALLOWED_HOSTS_HOSTNAME_LOOKUP': 'no'}

        # reqd[0]: required field name
        # reqd[1]: is value required? (False = value can be blank)
        self.reqd = (('DENY_THRESHOLD', True),
                     ('DENY_THRESHOLD_VALID', True),
                     ('DENY_THRESHOLD_ROOT', True),
                     ('SECURE_LOG', True),
                     ('LOCK_FILE', True),
                     ('BLOCK_SERVICE', False),
                     ('PURGE_DENY', False),
                     ('HOSTS_DENY', True),
                     ('WORK_DIR', True))

        # the paths for these keys will be converted to
        # absolute pathnames (in the event they are relative)
        # since the --daemon mode requires absolute pathnames
        self.make_abs = ('WORK_DIR',
                         'LOCK_FILE',
                         'SECURE_LOG',
                         'HOSTS_DENY',
                         'DAEMON_LOG')

        # these settings are converted to numeric values
        self.to_int = ('DENY_THRESHOLD', 
                       'DENY_THRESHOLD_VALID',
                       'DENY_THRESHOLD_ROOT')
                
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
        self.make_absolute()


    def make_absolute(self):
        for key in self.make_abs:
            val = self.__data[key]
            if val:
                self.__data[key] = os.path.abspath(val)


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

    
    def dump_to_logger(self):
        keys = self.__data.keys()
        info("DenyHosts configuration settings:")
        for key in keys:
            info("   %s: [%s]", key, self.__data[key])
