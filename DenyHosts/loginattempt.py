import os
import logging

from counter import Counter
from constants import *

debug = logging.getLogger("loginattempt").debug
info = logging.getLogger("loginattempt").info

class LoginAttempt:
    def __init__(self, work_dir, deny_threshold, allowed_hosts,
                 suspicious_always=1, first_time=0, fetch_all=1):
        self.__work_dir = work_dir
        self.__deny_threshold = deny_threshold
        self.__first_time = first_time
        self.__suspicious_always = suspicious_always
        self.__allowed_hosts = allowed_hosts

        if fetch_all:
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

    def save_abusive_hosts(self, abusive_hosts=None):
        if not abusive_hosts:
            abusive_hosts = self.__abusive_hosts
        self.__save_stats(ABUSIVE_HOSTS, abusive_hosts)

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
        

class AbusiveHosts(LoginAttempt):
    def __init__(self, work_dir):
        LoginAttempt.__init__(self,
                              work_dir,
                              None,
                              None,
                              fetch_all = 0)
        self.__abusive_hosts = self.get_abusive_hosts()
        
    def save_abusive_hosts(self):
        LoginAttempt.save_abusive_hosts(self,
                                        self.__abusive_hosts)

    def purge_host(self, host):
        try:
            self.__abusive_hosts[host] = None
            del self.__abusive_hosts[host]
        except:
            pass

    def purge_hosts(self, hosts):
        info("purging_hosts: %s", str(hosts))
        for host in hosts:
            self.purge_host(host)
