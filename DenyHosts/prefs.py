import os, sys, re
from util import die, calculate_seconds, is_true
from regex import PREFS_REGEX
import logging

debug = logging.getLogger("prefs").debug
info = logging.getLogger("prefs").info


ENVIRON_REGEX = re.compile(r"""\$\[(?P<environ>[A-Z_]*)\]""")

try:
    set = set
except:
    from sets import Set
    set = Set


class Prefs(dict):
    def __getitem__(self, k):
        return self.get(k)
    
    def __init__(self, path=None):
        # default values for some of the configurable items
        self.__data = {'ADMIN_EMAIL': None,
                       'SUSPICIOUS_LOGIN_REPORT_ALLOWED_HOSTS': 'yes',
                       'HOSTNAME_LOOKUP': 'yes',
                       'SYSLOG_REPORT': 'no',
                       'DAEMON_LOG': '/var/log/denyhosts',
                       'DAEMON_SLEEP': '30s',
                       'DAEMON_PURGE': '1h',
                       'DAEMON_LOG_TIME_FORMAT': None,
                       'DAEMON_LOG_MESSAGE_FORMAT': '%(asctime)s - %(name)-12s: %(levelname)-8s %(message)s',
                       'AGE_RESET_INVALID': None,
                       'AGE_RESET_VALID': None,
                       'AGE_RESET_ROOT': None,
                       'AGE_RESET_RESTRICTED': None,
                       'RESET_ON_SUCCESS': 'no',
                       'PLUGIN_DENY': None,
                       'PLUGIN_PURGE': None,
                       'IPTABLES': None,
                       'BLOCKPORT': None,
                       'PFCTL_PATH': None,
                       'PF_TABLE': None,
                       'SMTP_USERNAME': None,
                       'SMTP_PASSWORD': None,
                       'SMTP_DATE_FORMAT': "%a, %d %b %Y %H:%M:%S %z",
                       'SSHD_FORMAT_REGEX': None,
                       'FAILED_ENTRY_REGEX': None,
                       'FAILED_ENTRY_REGEX2': None,
                       'FAILED_ENTRY_REGEX3': None,
                       'FAILED_ENTRY_REGEX4': None,
                       'FAILED_ENTRY_REGEX5': None,
                       'FAILED_ENTRY_REGEX6': None,
                       'FAILED_ENTRY_REGEX7': None,
#                       'FAILED_ENTRY_REGEX8': None,
#                       'FAILED_ENTRY_REGEX9': None,
#                       'FAILED_ENTRY_REGEX10': None,
                       'USERDEF_FAILED_ENTRY_REGEX': [],
                       'SUCCESSFUL_ENTRY_REGEX': None,
                       'SYNC_INTERVAL': '1h',
                       'SYNC_SERVER': None,
                       'SYNC_UPLOAD': "yes",
                       'SYNC_DOWNLOAD': "yes",
                       'SYNC_DOWNLOAD_THRESHOLD': 3,
                       'SYNC_DOWNLOAD_RESILIENCY': '5h',
                       'PURGE_THRESHOLD': 0,
                       'ALLOWED_HOSTS_HOSTNAME_LOOKUP': 'no'}

        # reqd[0]: required field name
        # reqd[1]: is value required? (False = value can be blank)
        self.reqd = (('DENY_THRESHOLD_INVALID', True),
                     ('DENY_THRESHOLD_VALID', True),
                     ('DENY_THRESHOLD_ROOT', True),
                     ('DENY_THRESHOLD_RESTRICTED', True),
                     ('SECURE_LOG', True),
                     ('LOCK_FILE', True),
                     ('BLOCK_SERVICE', False),
                     ('PURGE_DENY', False),
                     ('HOSTS_DENY', True),
                     ('WORK_DIR', True),
                     ('ETC_DIR', True),
                     ('IPTABLES', False),
                     ('BLOCKPORT', False),
                     ('PFCTL_PATH', False),
                     ('PF_TABLE', False))
        
        # the paths for these keys will be converted to
        # absolute pathnames (in the event they are relative)
        # since the --daemon mode requires absolute pathnames
        self.make_abs = ('WORK_DIR',
                         'ETC_DIR',
                         'LOCK_FILE',
                         'SECURE_LOG',
                         'HOSTS_DENY',
                         'DAEMON_LOG',
                         'IPTABLES',
                         'PFCTL_PATH')

        # these settings are converted to numeric values
        self.to_int = set(('DENY_THRESHOLD',
                           'DENY_THRESHOLD_INVALID', 
                           'DENY_THRESHOLD_VALID',
                           'DENY_THRESHOLD_ROOT',
                           'DENY_THRESHOLD_RESTRICTED',
                           'SYNC_DOWNLOAD_THRESHOLD',
                           'PURGE_THRESHOLD'))

        # these settings are converted from timespec format
        # to number of seconds (ie. "1m" -> 60)
        self.to_seconds = set(('PURGE_DENY',
                               'DAEMON_PURGE',
                               'DAEMON_SLEEP',
                               'AGE_RESET_VALID',
                               'AGE_RESET_INVALID',
                               'AGE_RESET_RESTRICTED',
                               'SYNC_INTERVAL',
                               'SYNC_DOWNLOAD_RESILIENCY',
                               'AGE_RESET_ROOT'))


        self.process_defaults()
        if path: self.load_settings(path)

    def process_defaults(self):
        for name in self.to_seconds:
            try:
                self.__data[name] = calculate_seconds(self.__data[name])
            except:
                pass

        
    def load_settings(self, path):
        try:
            fp = open(path, "r")
        except Exception, e :
            die("Error reading file: %s" % path, e)


        for line in fp:
            line = line.strip()
            if not line or line[0] in ('\n', '#'):
                continue
            try:
                m = PREFS_REGEX.search(line)
                if m:
                    name = m.group('name').upper()
                    value = self.environ_sub(m.group('value'))
                    
                    #print name, value
                    if not value: value = None
                    if name in self.to_int:
                        value = int(value)
                    if name in self.to_seconds and value:
                        value = calculate_seconds(value)
                    if name == 'USERDEF_FAILED_ENTRY_REGEX':
                        self.__data['USERDEF_FAILED_ENTRY_REGEX'].append(re.compile(value))
                    else:
                        self.__data[name] = value
            except Exception, e:
                fp.close()
                die("Error processing configuration parameter %s: %s" % (name, e))
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
                if name_reqd == 'DENY_THRESHOLD_INVALID':
                    print "\nNote: The configuration parameter DENY_THRESHOLD has been renamed"
                    print "      DENY_THRESHOLD_INVALID.  Please update your DenyHosts configuration"
                    print "      file to reflect this change."

                    if self.__data.has_key('DENY_THRESHOLD'):
                        print "\n*** Using deprecated DENY_THRESHOLD value for DENY_THRESHOLD_INVALID ***"
                        self.__data['DENY_THRESHOLD_INVALID'] = self.__data['DENY_THRESHOLD']
                    else:
                        ok = 0                        
                elif name_reqd == 'DENY_THRESHOLD_RESTRICTED':
                    print "\nNote: DENY_THRESHOLD_RESTRICTED has not been defined. Setting this"
                    print "value to DENY_THRESHOLD_ROOT"
                    self.__data['DENY_THRESHOLD_RESTRICTED'] = self.__data['DENY_THRESHOLD_ROOT']
                else:
                    ok = 0
            elif val_reqd and not self.__data[name_reqd]:
                print "Missing configuration value for: %s" % name_reqd
                ok = 0

        if not ok:
            die("You must correct these problems found in: %s" % path)


    def environ_sub(self, value):
        while True:
            environ_match = ENVIRON_REGEX.search(value)
            if not environ_match: return value
            name = environ_match.group("environ")
            env = os.environ.get(name)
            if not env:
                die("Could not find environment variable: %s" % name)
            value = ENVIRON_REGEX.sub(env, value)
                

    def get(self, name):
        return self.__data[name]



    def dump(self):
        print "Preferences:"
        keys = self.__data.keys()
        for key in keys:
            if key == 'USERDEF_FAILED_ENTRY_REGEX':
                for rx in self.__data[key]:
                    print "   %s: [%s]" % (key, rx.pattern)
            else:
                print "   %s: [%s]" % (key, self.__data[key])

    
    def dump_to_logger(self):
        keys = self.__data.keys()
        keys.sort()
        info("DenyHosts configuration settings:")
        for key in keys:
            if key == 'USERDEF_FAILED_ENTRY_REGEX':
                for rx in self.__data[key]:
                    info("   %s: [%s]" % (key, rx.pattern))
            else:
                info("   %s: [%s]", key, self.__data[key])

