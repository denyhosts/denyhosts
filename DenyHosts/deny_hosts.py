import os, sys
import string
import time
import socket
import gzip
try:
    import bz2
    HAS_BZ2 = True
except:
    HAS_BZ2 = False

    
import traceback
import logging
import signal
from stat import ST_SIZE, ST_INO
import re

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
from util import parse_host
from version import VERSION
from sync import Sync
from restricted import Restricted
import plugin

debug = logging.getLogger("denyhosts").debug
info = logging.getLogger("denyhosts").info
error = logging.getLogger("denyhosts").error
    
class DenyHosts:
    def __init__(self, logfile, prefs, lock_file,
                 ignore_offset=0, first_time=0,
                 noemail=0, daemon=0, foreground=0):
        self.__denied_hosts = {}
        self.__prefs = prefs
        self.__lock_file = lock_file
        self.__first_time = first_time
        self.__noemail = noemail
        self.__report = Report(prefs.get("HOSTNAME_LOOKUP"), is_true(prefs['SYSLOG_REPORT']))
        self.__daemon = daemon
        self.__foreground = foreground
        self.__sync_server = prefs.get('SYNC_SERVER')
        self.__sync_upload = is_true(prefs.get("SYNC_UPLOAD"))
        self.__sync_download = is_true(prefs.get("SYNC_DOWNLOAD"))
        self.__iptables = prefs.get("IPTABLES")
        self.__blockport = prefs.get("BLOCKPORT")
        self.__pfctl = prefs.get("PFCTL_PATH")
        self.__pftable = prefs.get("PF_TABLE")

        r = Restricted(prefs)
        self.__restricted = r.get_restricted()
        info("restricted: %s", self.__restricted)
        self.init_regex()
        
        try:
            self.file_tracker = FileTracker(self.__prefs.get('WORK_DIR'),
                                            logfile)
        except Exception, e:
            self.__lock_file.remove()
            die("Can't read: %s" % logfile, e)

        self.__allowed_hosts = AllowedHosts(self.__prefs)

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
                last_offset = offset
        elif not daemon:
            info("Log file size has not changed.  Nothing to do.")

            
        if daemon and not foreground:
            info("launching DenyHost daemon (version %s)..." % VERSION)
            #logging.getLogger().setLevel(logging.WARN)

            # remove lock file since createDaemon will
            # create a new pid.  A new lock
            # will be created when runDaemon is invoked
            self.__lock_file.remove()
            
            retCode = createDaemon()
            if retCode == 0:
                self.runDaemon(logfile, last_offset)
            else:
                die("Error creating daemon: %s (%d)" % (retCode[1], retCode[0]))
        elif foreground:
            info("launching DenyHost (version %s)..." % VERSION)
            self.__lock_file.remove()
            self.runDaemon(logfile, last_offset)


    def killDaemon(self, signum, frame):
        debug("Received SIGTERM")
        info("DenyHosts daemon is shutting down")
        # signal handler

        # self.__lock_file.remove()
        # lock will be freed on SIGTERM by denyhosts.py
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
        #signal.signal(signal.SIGHUP, self.killDaemon)
        signal.signal(signal.SIGTERM, self.killDaemon)
        signal.signal(signal.SIGUSR1, self.toggleDebug)
        info("DenyHost daemon is now running, pid: %s", os.getpid())
        info("send daemon process a TERM signal to terminate cleanly")
        info("  eg.  kill -TERM %s", os.getpid())
        self.__lock_file.create()  

        info("monitoring log: %s", logfile)
        daemon_sleep = self.__prefs.get('DAEMON_SLEEP')
        purge_time = self.__prefs.get('PURGE_DENY')
        sync_time = self.__prefs.get('SYNC_INTERVAL')
        info("sync_time: %s", str(sync_time))
        
        if purge_time:
            daemon_purge = self.__prefs.get('DAEMON_PURGE')
            daemon_purge = max(daemon_sleep, daemon_purge)
            purge_sleep_ratio = daemon_purge / daemon_sleep
            self.purge_counter = 0
            info("daemon_purge:      %ld", daemon_purge)
            info("daemon_sleep:      %ld", daemon_sleep)
            info("purge_sleep_ratio: %ld", purge_sleep_ratio)
        else:
            purge_sleep_ratio = None
            info("purging of %s is disabled", self.__prefs.get('HOSTS_DENY'))


        if sync_time and self.__sync_server:
            if sync_time < SYNC_MIN_INTERVAL:
                info("SYNC_INTERVAL (%d) should be atleast %d",
                     sync_time,
                     SYNC_MIN_INTERVAL)
                sync_time = SYNC_MIN_INTERVAL
            sync_time = max(daemon_sleep, sync_time)
            info("sync_time:      : %ld", sync_time)
            sync_sleep_ratio = sync_time / daemon_sleep
            self.sync_counter = 0
            info("sync_sleep_ratio: %ld", sync_sleep_ratio)
        else:
            sync_sleep_ratio = None
            info("denyhost synchronization disabled")

        self.daemonLoop(logfile, last_offset, daemon_sleep,
                        purge_time, purge_sleep_ratio, sync_sleep_ratio)


    def daemonLoop(self, logfile, last_offset, daemon_sleep,
                   purge_time, purge_sleep_ratio, sync_sleep_ratio):

        fp = open(logfile, "r")
        inode = os.fstat(fp.fileno())[ST_INO]

        while 1:           

            try:
                curr_inode = os.stat(logfile)[ST_INO]
            except:
                info("%s has been deleted", logfile)
                self.sleepAndPurge(daemon_sleep,
                                   purge_time,
                                   purge_sleep_ratio)
                continue

            if curr_inode != inode:
                info("%s has been rotated", logfile)
                inode = curr_inode
                try:
                    fp.close()
                except:
                    pass
                
                fp = open(logfile, "r")
                # this ultimately forces offset (if not 0) to be < last_offset
                last_offset = sys.maxint

                
            offset = os.fstat(fp.fileno())[ST_SIZE]
            if last_offset == None: last_offset = offset               

            if offset > last_offset:
                # new data added to logfile
                debug("%s has additional data", logfile)
               
                self.get_denied_hosts()
                last_offset = self.process_log(logfile, last_offset)

                self.file_tracker.save_offset(last_offset)
            elif offset == 0:
                # log file rotated, nothing to do yet...
                # since there is no first_line
                debug("%s is empty.  File was rotated", logfile)
            elif offset < last_offset:
                # file was rotated or replaced and now has data
                debug("%s most likely rotated and now has data", logfile)
                last_offset = 0
                self.file_tracker.update_first_line()
                continue

            self.sleepAndPurge(daemon_sleep, purge_time,
                               purge_sleep_ratio, sync_sleep_ratio)



    def sleepAndPurge(self, sleep_time, purge_time,
                      purge_sleep_ratio = None, sync_sleep_ratio = None):
        time.sleep(sleep_time)
        if purge_time:
            self.purge_counter += 1
            if self.purge_counter == purge_sleep_ratio:
                try:
                    purge = Purge(self.__prefs,
                                  purge_time)
                except Exception, e:
                    logging.getLogger().exception(e)
                    raise
                self.purge_counter = 0

        if sync_sleep_ratio:
            #debug("sync count: %d", self.sync_counter)
            self.sync_counter += 1
            if self.sync_counter == sync_sleep_ratio:
                try:
                    sync = Sync(self.__prefs)
                    if self.__sync_upload:
                        debug("sync upload")
                        timestamp = sync.send_new_hosts()
                    if self.__sync_download:
                        debug("sync download")
                        new_hosts = sync.receive_new_hosts()
                        if new_hosts:
                            info("received new hosts: %s", str(new_hosts))
                            self.get_denied_hosts()
                            self.update_hosts_deny(new_hosts)
                    sync.xmlrpc_disconnect()
                except Exception, e:
                    logging.getLogger().exception(e)
                    raise
                self.sync_counter = 0
        

    def get_denied_hosts(self):
        self.__denied_hosts = {}
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
            self.__allowed_hosts.clear_warned_hosts()


    def update_hosts_deny(self, deny_hosts):
        if not deny_hosts: return None, None

        #info("keys: %s", str( self.__denied_hosts.keys()))
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
                fp.write("%s %s%s%s\n" % (DENY_DELIMITER,
                                          time.asctime(),
                                          ENTRY_DELIMITER,
                                          output))
            fp.write("%s\n" % output)

        plugin_deny = self.__prefs.get('PLUGIN_DENY')
        if plugin_deny: plugin.execute(plugin_deny, new_hosts)
        if self.__iptables:
           debug("Trying to create iptables rules")
           try:
              for host in new_hosts:
                  my_host = str(host)
                  if self.__blockport:
                     new_rule = self.__iptables + " -I INPUT -p tcp --dport " + self.__blockport + " -s " + my_host + " -j DROP"
                  else:
                     new_rule = self.__iptables + " -I INPUT -s " + my_host + " -j DROP"
                  debug("Running iptabes rule: %s", new_rule)
                  info("Creating new firewall rule %s", new_rule)
                  os.system(new_rule);
           
           except Exception, e:
               print e
               print "Unable to write new firewall rule."

        if self.__pfctl and self.__pftable:
             debug("Trying to update PF table.")
             try:
               for host in new_hosts:
                   my_host = str(host)
                   new_rule = self.__pfctl + " -t " + self.__pftable + " -T add " + my_host
                   debug("Running PF update rule: %s", new_rule)
                   info("Creating new PF rule %s", new_rule)
                   os.system(new_rule);
            
             except Exception, e:
                print e
                print "Unable to write new PF rule."


        if fp != sys.stdout:
            fp.close()

        return new_hosts, status
    

    def is_valid(self, rx_match):
        invalid = 0
        try:
            if rx_match.group("invalid"): invalid = 1
        except:
            invalid = 1
        return invalid
    
    def process_log(self, logfile, offset):
        try:
            if logfile.endswith(".gz"):
                fp = gzip.open(logfile)
            elif logfile.endswith(".bz2"):
                if HAS_BZ2: fp = bz2.BZ2File(logfile, "r")
                else:       raise Exception, "Can not open bzip2 file (missing bz2 module)"
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
        
        login_attempt = LoginAttempt(self.__prefs,
                                     self.__allowed_hosts,
                                     suspicious_always,
                                     self.__first_time,
                                     1, # fetch all
                                     self.__restricted)

        for line in fp:
            success = invalid = 0
            m = None
            sshd_m = self.__sshd_format_regex.match(line)
            if sshd_m:
                message = sshd_m.group('message')
                
                # did this line match any of the fixed failed regexes?
                for i in FAILED_ENTRY_REGEX_RANGE:
                    rx = self.__failed_entry_regex_map.get(i)
                    if rx == None: continue
                    m = rx.search(message) 
                    if m:
                        invalid = self.is_valid(m)
                        break
                else: # didn't match any of the failed regex'es, was it succesful?
                    m = self.__successful_entry_regex.match(message)
                    if m:
                        success = 1

            # otherwise, did the line match one of the userdef regexes?
            if not m:
                for rx in self.__prefs.get('USERDEF_FAILED_ENTRY_REGEX'):
                    m = rx.search(line)
                    if m:
                        #info("matched: %s" % rx.pattern)
                        invalid = self.is_valid(m)
                        break

            if not m:
                # line isn't important
                continue

            try:
                user = m.group("user")
            except:
                user = ""
            try:
                host = m.group("host")
            except:
                error("regex pattern ( %s ) is missing 'host' group" % m.re.pattern)
                continue
            
            debug ("user: %s - host: %s - success: %d - invalid: %d",
                   user,
                   host,
                   success,
                   invalid)
            login_attempt.add(user, host, success, invalid)

        offset = fp.tell()
        fp.close()

        login_attempt.save_all_stats()
        deny_hosts = login_attempt.get_deny_hosts()

        #print deny_hosts
        new_denied_hosts, status = self.update_hosts_deny(deny_hosts)
        if new_denied_hosts:
            if not status:
                msg = "WARNING: Could not add the following hosts to %s" % self.__prefs.get('HOSTS_DENY')
            else:
                msg = "Added the following hosts to %s" % self.__prefs.get('HOSTS_DENY')
            self.__report.add_section(msg, new_denied_hosts)
            if self.__sync_server: self.sync_add_hosts(new_denied_hosts)
            plugin_deny = self.__prefs.get('PLUGIN_DENY')
            if plugin_deny: plugin.execute(plugin_deny, new_denied_hosts)
        
        new_suspicious_logins = login_attempt.get_new_suspicious_logins()
        if new_suspicious_logins:
            msg = "Observed the following suspicious login activity"
            self.__report.add_section(msg, new_suspicious_logins.keys())

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
                # send the report via email if configured
                send_email(self.__prefs, self.__report.get_report())
            elif not self.__daemon:
                # otherwise, if not in daemon mode, log the report to the console
                info(self.__report.get_report())                
            self.__report.clear()
            
        return offset


    def sync_add_hosts(self, hosts):
        try:
            filename = os.path.join(self.__prefs.get("WORK_DIR"), SYNC_HOSTS)
            fp = open(filename, "a") 
            for host in hosts:
                fp.write("%s\n" % host)
            fp.close()
            os.chmod(filename, 0644)
        except Exception, e:
            error(str(e))

    def get_regex(self, name, default):
        val = self.__prefs.get(name)
        if not val: 
            return default
        else:
            return re.compile(val)   


    def init_regex(self):
        self.__sshd_format_regex = self.get_regex('SSHD_FORMAT_REGEX', SSHD_FORMAT_REGEX)

        self.__successful_entry_regex = self.get_regex('SUCCESSFUL_ENTRY_REGEX',
                                                       SUCCESSFUL_ENTRY_REGEX)

        self.__failed_entry_regex_map = {}
        for i in FAILED_ENTRY_REGEX_RANGE:
            if i == 1: extra = ""
            else: extra = "%i" % i
            self.__failed_entry_regex_map[i] = self.get_regex('FAILED_ENTRY_REGEX%s' % extra,
                                                              FAILED_ENTRY_REGEX_MAP[i])

            
##        self.__failed_entry_regex = self.get_regex('FAILED_ENTRY_REGEX', FAILED_ENTRY_REGEX)
##        self.__failed_entry_regex2 = self.get_regex('FAILED_ENTRY_REGEX2', FAILED_ENTRY_REGEX2)
##        self.__failed_entry_regex3 = self.get_regex('FAILED_ENTRY_REGEX3', FAILED_ENTRY_REGEX3)
##        self.__failed_entry_regex4 = self.get_regex('FAILED_ENTRY_REGEX4', FAILED_ENTRY_REGEX4)
##        self.__failed_entry_regex5 = self.get_regex('FAILED_ENTRY_REGEX5', FAILED_ENTRY_REGEX5)
##        self.__failed_entry_regex6 = self.get_regex('FAILED_ENTRY_REGEX6', FAILED_ENTRY_REGEX6)
##        self.__failed_entry_regex6 = self.get_regex('FAILED_ENTRY_REGEX7', FAILED_ENTRY_REGEX7)
##        self.__failed_entry_regex6 = self.get_regex('FAILED_ENTRY_REGEX8', FAILED_ENTRY_REGEX8)
##        self.__failed_entry_regex6 = self.get_regex('FAILED_ENTRY_REGEX9', FAILED_ENTRY_REGEX9)
##        self.__failed_entry_regex6 = self.get_regex('FAILED_ENTRY_REGEX10', FAILED_ENTRY_REGEX10)

       
# vim: set sw=4 et :
