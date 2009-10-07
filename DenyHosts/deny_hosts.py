import os, sys
import string
import time
import socket
import gzip
import bz2
import traceback
import logging
import signal

from util import die, is_true, is_false, send_email
from allowedhosts import AllowedHosts
from loginattempt import LoginAttempt
from lockfile import LockFile
from filetracker import FileTracker
from prefs import Prefs
from report import Report
from version import VERSION
from constants import *
from regex import *
from daemon import createDaemon
from denyfileutil import Purge
from util import parse_host, calculate_seconds

debug = logging.getLogger("denyhosts").debug
info = logging.getLogger("denyhosts").info

    
class DenyHosts:
    def __init__(self, logfile, prefs, lock_file,
                 ignore_offset=0, first_time=0,
                 noemail=0, daemon=0):
        self.__denied_hosts = {}
        self.__prefs = prefs
        self.__lock_file = lock_file
        self.__first_time = first_time
        self.__noemail = noemail
        self.__report = Report(self.__prefs.get("HOSTNAME_LOOKUP"))
        self.__daemon = daemon
        
        try:
            self.file_tracker = FileTracker(self.__prefs.get('WORK_DIR'),
                                            logfile)
        except Exception, e:
            self.__lock_file.remove()
            die("Can't read: %s" % logfile, e)

        self.__allowed_hosts = AllowedHosts(self.__prefs.get('WORK_DIR'))

        if ignore_offset:
            last_offset = 0
        else:
            last_offset = self.file_tracker.get_offset()


        if last_offset != None:
            self.get_denied_hosts()
            info("Processing log file (%s) from offset (%ld)",
                 logfile,
                 last_offset)
            offset = self.process_log(logfile, last_offset)
            if offset != last_offset:
                self.file_tracker.save_offset(offset)
        elif not daemon:
            info("Log file size has not changed.  Nothing to do.")

            
        if daemon:
            info("launching DenyHosts daemon...")
            #logging.getLogger().setLevel(logging.WARN)

            # remove lock file since createDaemon will
            # close all file descriptors.  A new lock
            # will be created when runDaemon is invoked
            self.__lock_file.remove()
            createDaemon(self.runDaemon,
                         logfile,
                         last_offset)


    def killDaemon(self, signum, frame):
        info("DenyHosts daemon is shutting down")
        # signal handler

        # self.__lock_file.remove()
        # lock will be freed on SIGHUP by denyhosts.py
        # exception handler (SystemExit)
        sys.exit(0)

    def toggleDebug(self, signum, frame):
        level = logging.getLogger().getEffectiveLevel()
        if level == logging.INFO:
            level = logging.DEBUG
            name = "DEBUG"
        else:
            level = logging.INFO
            name = "INFO"
        info("setting debug level to: %s", name)
        logging.getLogger().setLevel(level)
        


    def runDaemon(self, logfile, last_offset):
        signal.signal(signal.SIGHUP, self.killDaemon)
        signal.signal(signal.SIGUSR1, self.toggleDebug)
        info("DenyHosts daemon is now running, pid: %s", os.getpid())
        info("send daemon process a HUP signal to terminate cleanly")
        info("  eg.  kill -HUP %s", os.getpid())
        self.__lock_file.create()  

        secure_log = self.__prefs.get('SECURE_LOG')
        info("monitoring log: %s", secure_log)
        daemon_sleep = calculate_seconds(self.__prefs.get('DAEMON_SLEEP'))
        purge_time = self.__prefs.get('PURGE_DENY')
        if purge_time:
            daemon_purge = calculate_seconds(self.__prefs.get('DAEMON_PURGE'))
            daemon_purge = max(daemon_sleep, daemon_purge)
            purge_sleep_ratio = daemon_purge / daemon_sleep
            info("daemon_purge:      %ld", daemon_purge)
            info("daemon_sleep:      %ld", daemon_sleep)
            info("purge_sleep_ratio: %ld", purge_sleep_ratio)
        else:
            daemon_purge = None
            info("purging of %s is disabled", self.__prefs.get('HOSTS_DENY'))

        fp = open(logfile, "r")

        i = 0
        while 1:
            fp.seek(0, 2)
            offset = fp.tell()
            if last_offset == None: last_offset = offset

            if offset > last_offset:
                # new data added to logfile
                debug("%s has additional data", secure_log)
               
                self.get_denied_hosts()
                last_offset = self.process_log(logfile, last_offset)

                self.file_tracker.save_offset(last_offset)
            elif offset == 0:
                # log file rotated, nothing to do yet...
                # since there is no first_line
                debug("%s is empty.  File was removed or rotated", secure_log)
            elif offset < last_offset:
                # file was rotated or replaced and now has data
                debug("%s most likely rotated and now has data", secure_log)
                last_offset = 0
                self.file_tracker.update_first_line()
                continue
            
            time.sleep(daemon_sleep)
            
            if daemon_purge:
                i += 1
                if i == purge_sleep_ratio:
                    try:
                        Purge(self.__prefs.get('HOSTS_DENY'),
                              purge_time,
                              self.__prefs.get('WORK_DIR'))
                    except Exception, e:
                        logging.getLogger().exception(e)
                        raise
                    i = 0

    

    def get_denied_hosts(self):
        for line in open(self.__prefs.get('HOSTS_DENY'), "r"):
            if line[0] not in ('#', '\n'):
                
                idx = line.find('#')
                if idx != 1:
                    line = line[:idx]
                    
                try:
                    host = parse_host(line)

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
        
        debug("new hosts: %s", str(new_hosts))
        
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
            if logfile.endswith(".gz"):
                fp = gzip.open(logfile)
            elif logfile.endswith(".bz2"):
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
                debug ("user: %s - host: %s - success: %d - invalid: %d",
                       user,
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
                msg = "WARNING: Could not add the following hosts to %s" % self.__prefs.get('HOSTS_DENY')
            else:
                msg = "Added the following hosts to %s" % self.__prefs.get('HOSTS_DENY')
            self.__report.add_section(msg, new_denied_hosts)
            
        new_suspicious_logins = login_attempt.get_new_suspicious_logins()
        if new_suspicious_logins:
            msg = "Observed the following suspicious login activity"
            self.__report.add_section(msg, new_suspicious_logins.items())

        if new_denied_hosts:
            info("new denied hosts: %s", str(new_denied_hosts))
        else:
            debug("no new denied hosts")

        if new_suspicious_logins:
            info("new suspicious logins: %s", str(new_suspicious_logins.keys()))
        else:
            debug("no new suspicious logins")

        if not self.__report.empty():
            if not self.__noemail:
                send_email(self.__prefs, self.__report.get_report())
            elif not self.__daemon:
                info(self.__report.get_report())
            self.__report.clear()
            
        return offset
