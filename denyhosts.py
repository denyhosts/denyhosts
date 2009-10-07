#!/usr/bin/env python
import os, sys
import re
import getopt
from smtplib import SMTP
import string
import time
import socket
from types import ListType, TupleType
import gzip
import bz2
import shutil
import traceback

try:
    from denyhosts_version import VERSION
except:
    VERSION = "unknown"   

plat = sys.platform
if plat.startswith("freebsd"):
    # this has no effect if BLOCK_SERVICE is empty
    BSD_STYLE = " : deny"
else:
    BSD_STYLE = ""

    
global DEBUG
DEBUG=0
CONFIG_FILE = "denyhosts.cfg"
TAB_OFFSET = 40
DENY_DELIMITER = "# DenyHosts:"
PURGE_TIME_LOOKUP = {'m': 60,       # minute
                     'h': 3600,     # hour
                     'd': 86400,    # day
                     'w': 604800,   # week
                     'y': 31536000} # year

#################################################################################
#        These files will be created relative to WORK_DIR                       #
#################################################################################
SECURE_LOG_OFFSET = "offset"
DENIED_TIMESTAMPS = "denied-timestamps"
ALLOWED_HOSTS = "allowed-hosts"
#PARSED_DATES = "file_dates"
ABUSIVE_HOSTS = "hosts"
ALLOWED_WARNED_HOSTS = "allowed-warned-hosts"
ABUSED_USERS_INVALID = "users-invalid"
ABUSED_USERS_VALID = "users-valid"
ABUSED_USERS_AND_HOSTS = "users-hosts"                              
SUSPICIOUS_LOGINS = "suspicious-logins"   # successful logins AFTER invalid
                                          #   attempts from same host

#################################################################################
# REGULAR EXPRESSIONS ARE COOL.  Check out Kodos (http://kodos.sourceforge.net) #
#################################################################################

#DATE_FORMAT_REGEX = re.compile(r"""(?P<month>[A-z]{3,3})\s*(?P<day>\d+)""")

SSHD_FORMAT_REGEX = re.compile(r""".* (sshd.*:|\[sshd\]) (?P<message>.*)""")
#SSHD_FORMAT_REGEX = re.compile(r""".* sshd.*: (?P<message>.*)""")

FAILED_ENTRY_REGEX = re.compile(r"""Failed (?P<method>.*) for (?P<invalid>invalid user |illegal user )?(?P<user>.*?) from (::ffff:)?(?P<host>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""")

FAILED_ENTRY_REGEX2 = re.compile(r"""(Illegal|Invalid) user (?P<user>.*?) from (::ffff:)?(?P<host>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""")

FAILED_ENTRY_REGEX3 = re.compile(r"""Authentication failure for (?P<user>.*) from (::ffff:)?(?P<host>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""")

FAILED_ENTRY_REGEX4 = re.compile(r"""Authentication failure for (?P<user>.*) from (?P<host>.*)""")

SUCCESSFUL_ENTRY_REGEX = re.compile(r"""Accepted (?P<method>.*) for (?P<user>.*?) from (::ffff:)?(?P<host>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""")

PREFS_REGEX = re.compile(r"""(?P<name>.*?)\s*[:=]\s*(?P<value>.*)""")

ALLOWED_REGEX = re.compile(r"""(?P<first_3bits>\d{1,3}\.\d{1,3}\.\d{1,3}\.)((?P<fourth>\d{1,3})|(?P<ip_wildcard>\*)|\[(?P<ip_range>\d{1,3}\-\d{1,3})\])""")

IP_ADDR_REGEX = re.compile(r"""(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""")

PURGE_TIME_REGEX = re.compile(r"""(?P<units>\d*)\s*(?P<period>[mhdwy])""")

#################################################################################

def die(msg, ex=None):
    print msg
    if ex: print ex
    sys.exit(1)


def is_true(s):
    s = s.lower()
    if s in ('1', 't', 'true', 'y', 'yes'):
        return True
    else:
        return False

def is_false(s):
    return not is_true(s)


def send_email(prefs, report_str):
    smtp = SMTP(prefs.get('SMTP_HOST'),
                prefs.get('SMTP_PORT'))

    msg = """From: %s
To: %s
Subject: %s
Date: %s

""" % (prefs.get('SMTP_FROM'),
       prefs.get('ADMIN_EMAIL'),
       prefs.get('SMTP_SUBJECT'),
       time.strftime("%a, %d %B %Y %H:%M:%S %Z"))

    msg += report_str
    try:
        smtp.sendmail(prefs.get('SMTP_FROM'),
                      prefs.get('ADMIN_EMAIL'),
                      msg)
        if DEBUG: print "sent email to: %s" % prefs.get("ADMIN_EMAIL")
    except Exception, e:
        print "Error sending email"
        print e
        print "Email message follows:"
        print msg
        
    smtp.quit()


def usage():
    print "Usage:  %s [-f logfile | --file=logfile] [ -c configfile | --config=configfile] [-i | --ignore] [-n | --noemail] [-u | --unlock] [--purge] [--migrate] [--version]" % sys.argv[0]
    print
    print " --file:   The name of log file to parse"
    print " --ignore: Ignore last processed offset (start processing from beginning)"
    print " --noemail: Do not send an email report"
    print " --unlock: if lockfile exists, remove it and run as normal"
    print " --migrate: migrate your HOSTS_DENY file so that it is suitable for --purge"
    print " --purge: expire entries older than your PURGE_DENY setting"
    print " --version: Prints the version of DenyHosts and exits"
    print
    print "Note: multiple --file args can be processed. ",
    print "If multiple files are provided, --ignore is implied"
    print

#################################################################################

class LockFile:
    def __init__(self, lockpath):
        self.lockpath = lockpath

    def exists(self):
        return os.access(self.lockpath, os.F_OK)


    def get_pid(self):
        pid = ""
        try:
            fp = open(self.lockpath, "r")
            pid = fp.read()
            fp.close()            
        except:
            pass
        return pid


    def create(self):
        fp = open(self.lockpath, "w")
        fp.write("%s\n" % os.getpid())
        fp.close()


    def remove(self, die_=True):
        try:
            os.unlink(self.lockpath)
        except Exception, e:
            if die_:
                die("Error deleting DenyHosts lock file: %s" % self.lockpath, e)

#################################################################################

class DenyFileUtilBase:
    def __init__(self, deny_file, extra_file_id=""):
        self.deny_file = deny_file
        self.backup_file = "%s.%s.bak" % (deny_file, extra_file_id)
        self.temp_file = "%s.%s.tmp" % (deny_file, extra_file_id)
        
    def backup(self):
        try:
            shutil.copy(self.deny_file, self.backup_file)
        except Exception, e:
            print e

    def replace(self):
        # overwrites deny_file with contents of temp_file
        try:
            os.rename(self.temp_file, self.deny_file)
        except Exception, e:
            print e

    def remove_temp(self):
        try:
            os.unlink(self.temp_file)
        except:
            pass

    def create_temp(self, data_list):
        raise Exception, "Not Imlemented"


    def get_data(self):
        data = []
        try:
            fp = open(self.backup_file, "r")
            data = fp.readlines()
            fp.close()
        except:
            pass
        return data

#################################################################################   

class Migrate(DenyFileUtilBase):
    def __init__(self, deny_file):
        DenyFileUtilBase.__init__(self, deny_file, "migrate")
        self.backup()
        self.create_temp(self.get_data())
        self.replace()

    def create_temp(self, data):
        try:
            fp = open(self.temp_file, "w")
            for line in data:
                if line.find("#") != -1:
                    fp.write(line)
                    continue
                
                line = line.strip()
                if not line:
                    fp.write("\n")
                    continue
                
                l = len(line)
                if l < TAB_OFFSET:
                    line = "%s%s" % (line, ' ' * (TAB_OFFSET - l))
            
                fp.write("%s %s %s\n" % (line,
                                         DENY_DELIMITER,
                                         time.asctime()))
            fp.close()
        except Exception, e:
            raise e
        
#################################################################################

class Purge(DenyFileUtilBase):
    def __init__(self, deny_file, purge_timestr):
        DenyFileUtilBase.__init__(self, deny_file, "purge")

        cutoff = self.calculate(purge_timestr)
        self.cutoff = long(time.time()) - cutoff
        if DEBUG:
            print "relative cutoff: %ld" % cutoff
            print "absolute cutoff: %ld" % self.cutoff
        
        self.backup()
        
        num_purged = self.create_temp(self.get_data())
        if num_purged > 0:
            self.replace()
        else:
            self.remove_temp()

    def calculate(self, timestr):
        m = PURGE_TIME_REGEX.search(timestr)
        if not m:
            raise Exception, "Invalid PURGE_TIME specification: string format"

        units = int(m.group('units'))
        period = m.group('period')

        if units == 0:
            raise Exception, "Invalid PURGE_TIME specification: units = 0"
        # anything older than cutoff will get removed
        return units * PURGE_TIME_LOOKUP[period]

        
    def create_temp(self, data):
        num_purged = 0
        try:
            fp = open(self.temp_file, "w")
            for line in data:
                delimiter_idx = line.find(DENY_DELIMITER)
                if delimiter_idx == -1:
                    fp.write(line)
                    continue
                
                entry = line[:delimiter_idx]
                delimiter_timestamp = line[delimiter_idx:].strip()
                timestamp = delimiter_timestamp.lstrip(DENY_DELIMITER)

                try:
                    tm = time.strptime(timestamp)
                except Exception, e:
                    print "Parse error -- Ignorning timestamp: %s" % timestamp
                    # ignoring bad time string
                    fp.write(line)
                    continue

                epoch = long(time.mktime(tm))
                #print entry, epoch, self.cutoff

                if self.cutoff > epoch:
                    num_purged += 1
                    if DEBUG: print "purging: %s" % entry
                    continue
                else:
                    fp.write(line)
                    continue
            fp.close()
        except Exception, e:
            raise e

        return num_purged
    
#################################################################################   


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

#################################################################################

class Report:
    def __init__(self, hostname_lookup):
        self.report = ""
        self.hostname_lookup = is_true(hostname_lookup)
        
    def empty(self):
        if self.report: return 0
        else: return 1
    
    def get_report(self):
        return self.report
    
    def add_section(self, message, iterable):
        self.report += "%s:\n\n" % message
        for i in iterable:
            if type(i) in (TupleType, ListType):
                extra = ": %d\n" % i[1]
                i = i[0]
            else:
                extra = ""
            if self.hostname_lookup:
                hostname = self.get_hostname(i)
                if DEBUG: print "get_host:", hostname
            else: hostname = i

            self.report += "%s%s\n" % (hostname, extra)
                
        self.report += "\n" + "-" * 70 + "\n"

        
    def get_hostname(self, text):
        m = IP_ADDR_REGEX.search(text)

        if m:
            start = m.start()
            ip = m.group('ip')
            text = text[:start]
        else:
            return text

        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return "%s (%s)" % (ip, hostname)
        except Exception, e:
            return "%s (unknown)" % ip
           
        
#################################################################################

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

    
#################################################################################


class FileTracker:
    def __init__(self, work_dir, logfile):
        self.work_dir = work_dir
        self.logfile = logfile
        (self.__first_line, self.__offset) = self.__get_current_offset()
        

    def __get_last_offset(self):
        path = os.path.join(self.work_dir,
                            SECURE_LOG_OFFSET)
        first_line = ""
        offset = 0L
        try:
            fp = open(path, "r")
            first_line = fp.readline()[:-1]
            offset = long(fp.readline())
        except:
            pass

        if DEBUG:
            print "__get_last_offset():"
            print "   first_line:", first_line
            print "   offset:", offset
            
        return first_line, offset


    def __get_current_offset(self):
        first_line = ""
        offset = 0L
        try:
            fp = open(self.logfile, "r")
            first_line = fp.readline()[:-1]
            fp.seek(0, 2)
            offset = fp.tell()
        except Exception, e:
            raise e

        if DEBUG:
            print "__get_current_offset():"
            print "   first_line:", first_line
            print "   offset:", offset
            
        return first_line, offset

    
    def get_offset(self):
        last_line, last_offset = self.__get_last_offset()


        if last_line != self.__first_line:
            # log file was rotated, start from beginning
            offset = 0L
        elif self.__offset > last_offset:
            # new lines exist in log file
            offset = last_offset
        else:
            # no new entries in log file
            offset = None

        if DEBUG:
            print "get_offset():"
            print "   offset:", offset
            
        return offset
    
        
    def save_offset(self, offset):
        path = os.path.join(self.work_dir,
                            SECURE_LOG_OFFSET)
        try:
            fp = open(path, "w")
            fp.write("%s\n" % self.__first_line)
            fp.write("%ld\n" % offset)
            fp.close()
        except:
            print "Could not save logfile offset to: %s" % path
            
        

#################################################################################
    

class LoginAttempt:
    def __init__(self, work_dir, deny_threshold, allowed_hosts, suspicious_always=1, first_time=0):
        self.__work_dir = work_dir
        self.__deny_threshold = deny_threshold
        self.__first_time = first_time
        self.__suspicious_always = suspicious_always
        self.__allowed_hosts = allowed_hosts
        
        self.__suspicious_logins = self.get_suspicious_logins()
        self.__valid_users = self.get_abused_users_valid()
        self.__invalid_users = self.get_abused_users_invalid()
        self.__valid_users_and_hosts = self.get_abused_users_and_hosts()
        self.__abusive_hosts = self.get_abusive_hosts()
        self.__new_suspicious_logins = Counter()


    def get_new_suspicious_logins(self):
        return self.__new_suspicious_logins

        
    def add(self, user, host, success, invalid):
        user_host_key = "%s - %s" % (user, host)

        if success and self.__abusive_hosts.get(host, 0) > self.__deny_threshold:
            num_failures = self.__valid_users_and_hosts.get(user_host_key, 0)
            self.__suspicious_logins[user_host_key] += 1
            if self.__suspicious_always or host not in self.__allowed_hosts:
                self.__new_suspicious_logins[user_host_key] += 1
            
        elif not success:
            self.__abusive_hosts[host] += 1
            if invalid:
                self.__invalid_users[user] += 1                
            else:
                self.__valid_users[user] += 1
                self.__valid_users_and_hosts[user_host_key] += 1


    def get_abusive_hosts(self):
        return self.__get_stats(ABUSIVE_HOSTS)

    def get_abused_users_invalid(self):
        return self.__get_stats(ABUSED_USERS_INVALID)

    def get_abused_users_valid(self):
        return self.__get_stats(ABUSED_USERS_VALID)

    def get_abused_users_and_hosts(self):
        return self.__get_stats(ABUSED_USERS_AND_HOSTS)

    def get_suspicious_logins(self):
        return self.__get_stats(SUSPICIOUS_LOGINS)

    def __get_stats(self, fname):
        path = os.path.join(self.__work_dir, fname)
        stats = Counter()
        try:
            for line in open(path, "r"):
                try:
                    name, value = line.split(":")
                    stats[name] = int(value)
                except:
                    pass                
        except Exception, e:
            if not self.__first_time: print e
            
        return stats


    def save_all_stats(self):
        self.save_abusive_hosts()
        self.save_abused_users_valid()
        self.save_abused_users_invalid()
        self.save_abused_users_and_hosts()
        self.save_suspicious_logins()

    def save_abusive_hosts(self):
        self.__save_stats(ABUSIVE_HOSTS, self.__abusive_hosts)

    def save_abused_users_invalid(self):
        self.__save_stats(ABUSED_USERS_INVALID, self.__invalid_users)

    def save_abused_users_valid(self):
        self.__save_stats(ABUSED_USERS_VALID, self.__valid_users)

    def save_abused_users_and_hosts(self):
        self.__save_stats(ABUSED_USERS_AND_HOSTS, self.__valid_users_and_hosts)

    def save_suspicious_logins(self):
        self.__save_stats(SUSPICIOUS_LOGINS, self.__suspicious_logins)

    def get_deny_hosts(self, threshold):
        hosts = self.__abusive_hosts.keys()
        deny_hosts = [host for host,num in self.__abusive_hosts.items()
                      if num > threshold]

        return deny_hosts
        

    def __save_stats(self, fname, stats):
        path = os.path.join(self.__work_dir, fname)
        try:
            fp = open(path, "w")
        except Exception, e:
            print e
            return

        
        keys = stats.keys()
        keys.sort()

        for key in keys:
            fp.write("%s:%d\n" % (key, stats[key]))
        fp.close()
        

#################################################################################

class AllowedHosts:
    def __init__(self, work_dir):
        self.allowed_path = os.path.join(work_dir, ALLOWED_HOSTS)
        self.warned_path = os.path.join(work_dir, ALLOWED_WARNED_HOSTS)
        self.allowed_hosts = {}
        self.warned_hosts = {}
        self.new_warned_hosts = []
        self.load_hosts()
        self.load_warned_hosts()

    def __contains__(self, ip_addr):
        if self.allowed_hosts.has_key(ip_addr): return 1
        else: return 0

    def dump(self):
        print "Dumping AllowedHosts"
        print self.allowed_hosts.keys()

        
    def load_hosts(self):
        try:
            fp = open(self.allowed_path, "r")
        except:
            return

        for line in fp:
            line = line.strip()
            if not line or line[0] == '#': continue

            m = ALLOWED_REGEX.match(line)
            if m:
                first3 = m.group('first_3bits')
                fourth = m.group('fourth')
                wildcard = m.group('ip_wildcard')
                ip_range = m.group('ip_range')

                if fourth:
                    self.allowed_hosts["%s%s" % (first3, fourth)] = 1
                elif wildcard:
                    for i in range(256):
                        self.allowed_hosts["%s%s" % (first3, i)] = 1
                else:
                    start, end = ip_range.split("-")
                    for i in range(int(start), int(end)):
                        self.allowed_hosts["%s%d" % (first3, i)] = 1
            
        fp.close()

    def add_warned_host(self, host):
        if host not in self.warned_hosts:
            self.new_warned_hosts.append(host)
            
    def get_new_warned_hosts(self):
        return self.new_warned_hosts
    

    def load_warned_hosts(self):
        try:
            fp = open(self.warned_path, "r")
            for line in fp:
                self.warned_hosts[line.strip()] = None
            fp.close()
        except:
            pass


    def save_warned_hosts(self):
        if not self.new_warned_hosts: return
        try:
            fp = open(self.warned_path, "a")
            for host in self.new_warned_hosts:
                fp.write("%s\n" % host)
            fp.close()
        except Exception, e:
            print e

            
#################################################################################

    
class DenyHosts:
    def __init__(self, logfile, prefs, lock_file,
                 ignore_offset=0, first_time=0, noemail=0, verbose=0):
        self.__denied_hosts = {}
        self.__prefs = prefs
        self.__lock_file = lock_file
        self.__first_time = first_time
        self.__noemail = noemail
        self.__verbose = verbose
        self.__report = Report(self.__prefs.get("HOSTNAME_LOOKUP"))

        try:
            file_tracker = FileTracker(self.__prefs.get('WORK_DIR'),
                                       logfile)
        except Exception, e:
            self.__lock_file.remove()
            die("Can't read: %s" % logfile, e)

        self.__allowed_hosts = AllowedHosts(self.__prefs.get('WORK_DIR'))

        if ignore_offset:
            last_offset = 0
        else:
            last_offset = file_tracker.get_offset()

        if last_offset != None:
            self.get_denied_hosts()
            if self.__verbose or DEBUG:
                print "Processing log file (%s) from offset (%ld)" % (logfile,
                                                                      last_offset)
            offset = self.process_log(logfile, last_offset)
            if offset != last_offset:
                file_tracker.save_offset(offset)
        else:
            if self.__verbose or DEBUG:
                print "Log file size has not changed.  Nothing to do."
                

    def get_denied_hosts(self):
        for line in open(self.__prefs.get('HOSTS_DENY'), "r"):
            if line[0] not in ('#', '\n'):
                
                idx = line.find('#')
                if idx != 1:
                    line = line[:idx]
                    
                try:
                    # the deny file can be in the form:
                    # 1) ip_address
                    # 2) sshd: ip_address
                    # 3) ip_address : deny
                    # 4) sshd: ip_address : deny

                    # convert form 3 & 4 to 1 & 2
                    line = line.strip(BSD_STYLE)
                    
                    vals = line.split(":")
                    
                    # we're only concerned about the ip_address
                    if len(vals) == 1: form = vals[0]
                    else: form = vals[1]
                    
                    host = form.strip()
                    self.__denied_hosts[host] = 0
                    if host in self.__allowed_hosts:
                        self.__allowed_hosts.add_warned_host(host)
                except:
                    pass

        new_warned_hosts = self.__allowed_hosts.get_new_warned_hosts()
        if new_warned_hosts:
            self.__allowed_hosts.save_warned_hosts()
            
            text = """WARNING: The following hosts appear in %s but should be
allowed based on your %s file"""  % (self.__prefs.get("HOSTS_DENY"),
                                     os.path.join(self.__prefs.get("WORK_DIR"),
                                                  ALLOWED_HOSTS))
            self.__report.add_section(text, new_warned_hosts)
            

    def update_hosts_deny(self, deny_hosts):
        if not deny_hosts: return None, None

        #print self.__denied_hosts.keys()
        new_hosts = [host for host in deny_hosts
                     if not self.__denied_hosts.has_key(host)
                     and host not in self.__allowed_hosts]
        #print new_hosts
        
        try:
            fp = open(self.__prefs.get('HOSTS_DENY'), "a")
            status = 1
        except Exception, e:
            print e
            print "These hosts should be manually added to",
            print self.__prefs.get('HOSTS_DENY')
            fp = sys.stdout
            status = 0

        write_timestamp = self.__prefs.get('PURGE_DENY') != None
        for host in new_hosts:
            block_service = self.__prefs.get('BLOCK_SERVICE')
            if block_service:
                block_service = "%s: " % block_service
                output = "%s%s%s" % (block_service, host, BSD_STYLE)
            else:
                output = "%s" % host

            if write_timestamp:
                l = len(output)
                if l < TAB_OFFSET:
                    output = "%s%s" % (output, ' ' * (TAB_OFFSET - l))
            
                fp.write("%s %s %s\n" % (output,
                                         DENY_DELIMITER,
                                         time.asctime()))
            else:
                fp.write("%s\n" % output)

        if fp != sys.stdout:
            fp.close()

        return new_hosts, status
    


    def process_log(self, logfile, offset):
        try:
            if f.endswith(".gz"):
                fp = gzip.open(logfile)
            elif f.endswith(".bz2"):
                fp = bz2.BZ2File(logfile, "r")
            else:
                fp = open(logfile, "r")
        except Exception, e:
            print "Could not open log file: %s" % logfile
            print e
            return -1

        try:
            fp.seek(offset)
        except:
            pass

        suspicious_always = is_true(self.__prefs.get('SUSPICIOUS_LOGIN_REPORT_ALLOWED_HOSTS'))
        
        login_attempt = LoginAttempt(self.__prefs.get('WORK_DIR'),
                                     self.__prefs.get('DENY_THRESHOLD'),
                                     self.__allowed_hosts,
                                     suspicious_always,
                                     self.__first_time)

        for line in fp:
            success = invalid = 0
            sshd_m = SSHD_FORMAT_REGEX.match(line)
            if not sshd_m: continue
            message = sshd_m.group('message')

            m = (FAILED_ENTRY_REGEX.match(message) or 
                 FAILED_ENTRY_REGEX2.match(message) or 
                 FAILED_ENTRY_REGEX3.match(message) or 
                 FAILED_ENTRY_REGEX4.match(message))
            if m:
                try:
                    if m.group("invalid"): invalid = 1
                except:
                    invalid = 1
            else:
                m = SUCCESSFUL_ENTRY_REGEX.match(message)
                if m:
                    success = 1
            if not m:
                continue
            
            if m:               
                user = m.group("user")
                host = m.group("host")
                if DEBUG:
                    print "user: %s - host: %s - success: %d - invalid: %d" % (user,
                                                                               host,
                                                                               success,
                                                                               invalid)
                login_attempt.add(user, host, success, invalid)
                    

        offset = fp.tell()
        fp.close()

        login_attempt.save_all_stats()
        deny_hosts = login_attempt.get_deny_hosts(self.__prefs.get('DENY_THRESHOLD'))

        #print deny_hosts
        new_denied_hosts, status = self.update_hosts_deny(deny_hosts)
        if new_denied_hosts:
            if not status:
                msg = "WARNING: Could not add the following hosts to %s" % prefs.get('HOSTS_DENY')
            else:
                msg = "Added the following hosts to %s" % prefs.get('HOSTS_DENY')
            self.__report.add_section(msg, new_denied_hosts)
            
        new_suspicious_logins = login_attempt.get_new_suspicious_logins()
        if new_suspicious_logins:
            msg = "Observed the following suspicious login activity"
            self.__report.add_section(msg, new_suspicious_logins.items())
        
        
        if self.__verbose or DEBUG:
            print "new denied hosts:", str(new_denied_hosts)
            print "new sucpicious logins:", str(new_suspicious_logins.keys())

        if not self.__report.empty():
            if not self.__noemail:
                send_email(self.__prefs, self.__report.get_report())
            else:
                print self.__report.get_report()
            
        return offset

#################################################################################

    
if __name__ == '__main__':
    logfiles = []
    config_file = CONFIG_FILE
    ignore_offset = 0
    noemail = 0
    verbose = 0
    unlock = 0
    migrate = 0
    purge = 0
    args = sys.argv[1:]
    try:
        (opts, getopts) = getopt.getopt(args, 'f:c:dinuvp?hV',
                                        ["file=", "ignore", "verbose", "debug", 
                                         "help", "noemail", "config=", "version",
                                         "unlock", "migrate", "purge"])
    except:
        print "\nInvalid command line option detected."
        usage()
        sys.exit(1)
    
    for opt, arg in opts:
        if opt in ('-h', '-?', '--help'):
            usage()
            sys.exit(0)
        if opt in ('-f', '--file'):
            logfiles.append(arg)
        if opt in ('-i', '--ignore'):
            ignore_offset = 1
        if opt in ('-n', '--noemail'):
            noemail = 1
        if opt in ('-v', '--verbose'):
            verbose = 1
            first_time = 0
        if opt in ('-d', '--debug'):
            DEBUG = 1            
        if opt in ('-c', '--config'):
            config_file = arg
        if opt in ('-u', '--unlock'):
            unlock = 1
        if opt in ('-m', '--migrate'):
            migrate = 1
        if opt in ('-p', '--purge'):
            purge = 1                        
        if opt == '--version':
            print "DenyHosts version:", VERSION
            sys.exit(0)

    prefs = Prefs(config_file)
    first_time = 0
    try:
        os.makedirs(prefs.get('WORK_DIR'))
        first_time = 1
    except Exception, e:
        if e[0] != 17:
            print e
            sys.exit(1)

    if DEBUG:
        print "Debug mode enabled."
        prefs.dump()
    
    if not logfiles:
        logfiles = [prefs.get('SECURE_LOG')]
    elif len(logfiles) > 1:
        ignore_offset = 1

    if not prefs.get('ADMIN_EMAIL'): noemail = 1

    lock_file = LockFile(prefs.get('LOCK_FILE'))

    if unlock and lock_file.exists():
        lock_file.remove(False)
    else:
        pid = lock_file.get_pid()
        if pid: die("DenyHosts is already running with pid: %s" % pid)

    lock_file.create()

    if migrate:
        if not prefs.get('PURGE_DENY'):
            lock_file.remove()
            die("You have supplied the --migrate flag however you have not set PURGE_DENY in your configuration file.")
        else:
            m = Migrate(prefs.get("HOSTS_DENY"))

    if purge:
        purge_time = prefs.get('PURGE_DENY')
        if not purge_time:
            lock_file.remove()
            die("You have provided the --purge flag however you have not set PURGE_DENY in your configuration file.")
        else:
            try:
                p = Purge(prefs.get('HOSTS_DENY'),
                          purge_time)
            except Exception, e:
                lock_file.remove()
                die(str(e))
        

    try:
        for f in logfiles:
            dh = DenyHosts(f, prefs, lock_file, ignore_offset,
                           first_time, noemail, verbose)
    except Exception, e:
        traceback.print_exc(e)
        
    lock_file.remove()
            
