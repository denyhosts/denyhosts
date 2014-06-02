import os
import logging
import errno
from util import is_true

try:
    set = set
except:
    from sets import Set
    set = Set

from counter import Counter, CounterRecord
from constants import *

debug = logging.getLogger("loginattempt").debug
info = logging.getLogger("loginattempt").info

class LoginAttempt:
    def __init__(self, prefs, allowed_hosts, suspicious_always=1,
                 first_time=0, fetch_all=1, restricted=None):
        if restricted == None: restricted = set()
        self.__restricted = restricted
        
        self.__work_dir = prefs.get('WORK_DIR')
        
        self.__deny_threshold_invalid = prefs.get('DENY_THRESHOLD_INVALID')
        self.__deny_threshold_valid = prefs.get('DENY_THRESHOLD_VALID')
        self.__deny_threshold_root = prefs.get('DENY_THRESHOLD_ROOT')
        self.__deny_threshold_restricted = prefs.get('DENY_THRESHOLD_RESTRICTED')

        self.__age_reset_invalid = prefs.get('AGE_RESET_INVALID')
        self.__age_reset_valid = prefs.get('AGE_RESET_VALID')
        self.__age_reset_root = prefs.get('AGE_RESET_ROOT')
        self.__age_reset_restricted = prefs.get('AGE_RESET_RESTRICTED')

        self.__reset_on_success = is_true(prefs.get('RESET_ON_SUCCESS'))
               
        self.__first_time = first_time
        self.__suspicious_always = suspicious_always
        self.__allowed_hosts = allowed_hosts

        if fetch_all:
            self.__suspicious_logins = self.get_suspicious_logins()
            self.__valid_users = self.get_abused_users_valid()
            self.__invalid_users = self.get_abused_users_invalid()
            self.__valid_users_and_hosts = self.get_abused_users_and_hosts()
            self.__abusive_hosts_valid = self.get_abusive_hosts_valid()
            self.__abusive_hosts_invalid = self.get_abusive_hosts_invalid()
            self.__abusive_hosts_root = self.get_abusive_hosts_root()
            self.__abusive_hosts_restricted = self.get_abusive_hosts_restricted()
            self.__new_suspicious_logins = Counter()


    def get_new_suspicious_logins(self):
        return self.__new_suspicious_logins

        
    def add(self, user, host, success, invalid):
        user_host_key = "%s - %s" % (user, host)

        if host:
            if self.__age_reset_invalid:              
                self.__abusive_hosts_invalid[host].age_count(self.__age_reset_invalid)
            if self.__age_reset_valid:        
                self.__abusive_hosts_valid[host].age_count(self.__age_reset_valid)
            if self.__age_reset_restricted:        
                self.__abusive_hosts_restricted[host].age_count(self.__age_reset_restricted)
            if self.__age_reset_root:        
                self.__abusive_hosts_root[host].age_count(self.__age_reset_root)


        if success and self.__reset_on_success:
            info("resetting count for: %s", host)
            self.__abusive_hosts_valid[host].reset_count()
            # ??? maybe:
            self.__abusive_hosts_invalid[host].reset_count()


        if success and self.__abusive_hosts_invalid.get(host, 0) > self.__deny_threshold_invalid:
            num_failures = self.__valid_users_and_hosts.get(user_host_key, 0)
            self.__suspicious_logins[user_host_key] += 1
            if self.__suspicious_always or host not in self.__allowed_hosts:
                self.__new_suspicious_logins[user_host_key] += 1            
        elif not success:
            if user in self.__restricted:
                self.increment_count(host,
                                     self.__abusive_hosts_restricted,
                                     self.__age_reset_restricted)
                
            if invalid:
                # username is invalid
                self.increment_count(host,
                                     self.__abusive_hosts_invalid,
                                     self.__age_reset_invalid)

                self.__invalid_users[user] += 1                
            else:
                # username is valid
                self.increment_count(user,
                                     self.__valid_users)

                self.increment_count(user_host_key,
                                     self.__valid_users_and_hosts)
                
                if user == 'root':
                    self.increment_count(host,
                                         self.__abusive_hosts_root,
                                         self.__age_reset_root)
                elif user in self.__restricted:
                    self.increment_count(host,
                                         self.__abusive_hosts_restricted,
                                         self.__age_reset_restricted)
                else:
                    self.increment_count(host,
                                         self.__abusive_hosts_valid,
                                         self.__age_reset_valid)

    def increment_count(self, key, count_inst, age_reset=None):
        #if not count_inst.has_key(key) or count_inst.has_key(key) and count_inst[key] is None:
        #    count_inst[key] = CounterRecord(0)
        
        #debug(count_inst)
        if age_reset:
            count_inst[key].age_count(age_reset)
        #debug(count_inst)
        count_inst[key] += 1
        #debug(count_inst)
        

    def get_abusive_hosts_invalid(self):
        return self.__get_stats(ABUSIVE_HOSTS_INVALID)

    def get_abusive_hosts_root(self):
        return self.__get_stats(ABUSIVE_HOSTS_ROOT)

    def get_abusive_hosts_restricted(self):
        return self.__get_stats(ABUSIVE_HOSTS_RESTRICTED)

    def get_abusive_hosts_valid(self):
        return self.__get_stats(ABUSIVE_HOSTS_VALID)

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
                    line = line.strip()
                    parts = line.split(":")
                    name = parts[0]
                    count = parts[1]
                    try:
                        date = ':'.join(parts[2:])
                    except:
                        date = None

                    stats[name] = CounterRecord(int(count), date)
                    #debug("stats[%s] = %s", name, stats[name])
                except Exception, e:
                    ##debug(e)
                    pass                
        except IOError, e:
            if e.errno == errno.ENOENT: debug("%s does not exist", fname)
            else: print e
        except Exception, e:
            if not self.__first_time: print e
            
        return stats


    def save_all_stats(self):
        self.save_abusive_hosts_valid()
        self.save_abusive_hosts_invalid()
        self.save_abusive_hosts_root()
        self.save_abusive_hosts_restricted()
        self.save_abused_users_valid()
        self.save_abused_users_invalid()
        self.save_abused_users_and_hosts()
        self.save_suspicious_logins()

    def save_abusive_hosts_invalid(self, abusive_hosts=None):
        if abusive_hosts is None:
            abusive_hosts = self.__abusive_hosts_invalid
        self.__save_stats(ABUSIVE_HOSTS_INVALID, abusive_hosts)

    def save_abusive_hosts_root(self, abusive_hosts=None):
        if abusive_hosts is None:
            abusive_hosts = self.__abusive_hosts_root
        self.__save_stats(ABUSIVE_HOSTS_ROOT, abusive_hosts)

    def save_abusive_hosts_restricted(self, abusive_hosts=None):
        if abusive_hosts is None:
            abusive_hosts = self.__abusive_hosts_restricted
        self.__save_stats(ABUSIVE_HOSTS_RESTRICTED, abusive_hosts)

    def save_abusive_hosts_valid(self, abusive_hosts=None):
        if abusive_hosts is None:
            abusive_hosts = self.__abusive_hosts_valid
        self.__save_stats(ABUSIVE_HOSTS_VALID, abusive_hosts)

    def save_abused_users_invalid(self):
        self.__save_stats(ABUSED_USERS_INVALID, self.__invalid_users)

    def save_abused_users_valid(self):
        self.__save_stats(ABUSED_USERS_VALID, self.__valid_users)

    def save_abused_users_and_hosts(self):
        self.__save_stats(ABUSED_USERS_AND_HOSTS, self.__valid_users_and_hosts)

    def save_suspicious_logins(self):
        self.__save_stats(SUSPICIOUS_LOGINS, self.__suspicious_logins)

    def get_deny_hosts(self):
        invalid_hosts = [host for host,count_rec in self.__abusive_hosts_invalid.items()
                         if count_rec.get_count() > self.__deny_threshold_invalid]

        root_hosts = [host for host,count_rec in self.__abusive_hosts_root.items()
                      if count_rec.get_count() > self.__deny_threshold_root]

        restricted_hosts = [host for host,count_rec in self.__abusive_hosts_restricted.items()
                            if count_rec.get_count() > self.__deny_threshold_restricted]

        valid_hosts = [host for host,count_rec in self.__abusive_hosts_valid.items()
                       if count_rec.get_count() > self.__deny_threshold_valid]

        deny_set = set(invalid_hosts + valid_hosts + root_hosts + restricted_hosts)
        return list(deny_set)
        

    def __save_stats(self, fname, stats):
        path = os.path.join(self.__work_dir, fname)
        if stats is None: 
            #debug("%s: is none", fname)
            return
        
        try:
            fp = open(path, "w")
        except Exception, e:
            print e
            return

        if not stats:
            # if stats dict is empty-- no data to process
            fp.close()
            return
 
        keys = stats.keys()
        keys.sort()

        for key in keys:
            #debug("")
            #debug("key: %s - stats[key]: %s", key, stats[key])
            #debug("stats: %s", stats)
            #debug("")
            fp.write("%s:%s\n" % (key, stats[key]))
        fp.close()
        

class AbusiveHosts(LoginAttempt):
    def __init__(self, prefs):
        LoginAttempt.__init__(self,
                              prefs,
                              None,
                              fetch_all = 0)
        self.__abusive_hosts_invalid = self.get_abusive_hosts_invalid()
        self.__abusive_hosts_root = self.get_abusive_hosts_root()
        self.__abusive_hosts_restricted = self.get_abusive_hosts_restricted()
        self.__abusive_hosts_valid = self.get_abusive_hosts_valid()
        
    def save_abusive_hosts(self):
        LoginAttempt.save_abusive_hosts_invalid(self,
                                                self.__abusive_hosts_invalid)

        LoginAttempt.save_abusive_hosts_root(self,
                                             self.__abusive_hosts_root)

        LoginAttempt.save_abusive_hosts_restricted(self,
                                                   self.__abusive_hosts_restricted)

        LoginAttempt.save_abusive_hosts_valid(self,
                                              self.__abusive_hosts_valid)

    def purge_host(self, host):
        try:
            self.__abusive_hosts_invalid[host] = None
            self.__abusive_hosts_root[host] = None
            self.__abusive_hosts_restricted[host] = None
            self.__abusive_hosts_valid[host] = None
            del self.__abusive_hosts_invalid[host]
            del self.__abusive_hosts_root[host]
            del self.__abusive_hosts_restricted[host]
            del self.__abusive_hosts_valid[host]
        except:
            pass

    def purge_hosts(self, hosts):
        info("purging_hosts: %s", str(hosts))
        for host in hosts:
            self.purge_host(host)
