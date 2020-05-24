import os
import shutil
import time
import logging

from .constants import DENY_DELIMITER, ENTRY_DELIMITER
from .loginattempt import AbusiveHosts
from .util import parse_host, get_user_input
from . import plugin
from .purgecounter import PurgeCounter

debug = logging.getLogger("denyfileutil").debug
info = logging.getLogger("denyfileutil").info
warn = logging.getLogger("denyfileutil").warning


class DenyFileUtilBase(object):
    def __init__(self, deny_file, extra_file_id=""):
        self.deny_file = deny_file
        self.backup_file = "%s.%s.bak" % (deny_file, extra_file_id)
        self.temp_file = "%s.%s.tmp" % (deny_file, extra_file_id)

    def backup(self):
        try:
            shutil.copy(self.deny_file, self.backup_file)
        except Exception as e:
            warn(str(e))

    def replace(self):
        # overwrites deny_file with contents of temp_file
        try:
            os.rename(self.temp_file, self.deny_file)
        except Exception as e:
            print(e)

    def remove_temp(self):
        try:
            os.unlink(self.temp_file)
        except OSError:
            pass

    def create_temp(self, data_list):
        raise Exception("Not Imlemented")

    def get_data(self):
        data = []
        try:
            fp = open(self.backup_file, "r")
            data = fp.readlines()
            fp.close()
        except IOError:
            pass
        return data

#################################################################################


class Migrate(DenyFileUtilBase):
    def __init__(self, deny_file):
        print("")
        print("**** WARNING ****")
        print("migrate switch will migrate ALL your entries in your HOSTS_DENY file")
        print("and this can be potentially dangerous, if you have some entry that ")
        print("you won't purge")
        print("")
        print("If you don't understand, please type 'No' and")
        print("refer to documentation for more info")
        print("")

        prompt = "Are you sure that you want do this? (Yes/No)"
        response = get_user_input(prompt)

        if response == "Yes":
            DenyFileUtilBase.__init__(self, deny_file, "migrate")
            self.backup()
            self.create_temp(self.get_data())
            self.replace()
        else:
            print("nothing done")

    def create_temp(self, data):
        try:
            fp = open(self.temp_file, "w")
            os.chmod(self.temp_file, 0o644)
            for line in data:
                if line.find("#") != -1:
                    fp.write(line)
                    continue

                line = line.strip()
                if not line:
                    fp.write("\n")
                    continue

                fp.write("%s %s%s%s\n" % (DENY_DELIMITER,
                                          time.asctime(),
                                          ENTRY_DELIMITER,
                                          line))
                fp.write("%s\n" % line)

            fp.close()
        except Exception as e:
            raise e

#################################################################################


class UpgradeTo099(DenyFileUtilBase):
    def __init__(self, deny_file):
        DenyFileUtilBase.__init__(self, deny_file, "0.9.9")
        self.backup()
        self.create_temp(self.get_data())
        self.replace()

    def create_temp(self, data):
        try:
            fp = open(self.temp_file, "w")
            for line in data:
                if line.find("#") == 0:
                    fp.write(line)
                    continue

                line = line.strip()
                if not line:
                    fp.write("\n")
                    continue

                delimiter_idx = line.find(DENY_DELIMITER)

                if delimiter_idx == -1:
                    fp.write("%s\n" % line)
                    continue

                entry = line[:delimiter_idx].strip()
                fp.write("%s%s%s\n" % (line[delimiter_idx:],
                                       ENTRY_DELIMITER,
                                       entry))
                fp.write("%s\n" % entry)
            fp.close()
        except Exception as e:
            raise e

#################################################################################


class Purge(DenyFileUtilBase):

    def __init__(self, prefs, cutoff):
        deny_file = prefs.get('HOSTS_DENY')
        DenyFileUtilBase.__init__(self, deny_file, "purge")
        self.__prefs = prefs
        self.work_dir = prefs.get('WORK_DIR')
        self.purge_threshold = prefs['PURGE_THRESHOLD']
        self.purge_counter = PurgeCounter(prefs)
        self.__plugin_purge = self.__prefs.get('PLUGIN_PURGE')
        self.cutoff = int(time.time()) - cutoff
        debug("relative cutoff: %ld (seconds)", cutoff)
        debug("absolute cutoff: %ld (epoch)", self.cutoff)
        info("purging entries older than: %s", time.asctime(time.localtime(self.cutoff)))

    def run_purge(self):
        self.backup()

        purged_hosts = self.create_temp(self.get_data())
        num_purged = len(purged_hosts)
        if num_purged > 0:
            self.replace()
            abusive_hosts = AbusiveHosts(self.__prefs)
            abusive_hosts.purge_hosts(purged_hosts)
            abusive_hosts.save_abusive_hosts()
            self.purge_counter.increment(purged_hosts)
        else:
            self.remove_temp()

        info("num entries purged: %d", num_purged)
        if self.__plugin_purge:
            plugin.execute(self.__plugin_purge, purged_hosts)

        if num_purged > 0:
            return purged_hosts
        return None

    def create_temp(self, data):
        purged_hosts = []
        banned = self.purge_counter.get_banned_for_life()

        try:
            fp = open(self.temp_file, "w")
            os.chmod(self.temp_file, 0o644)
            offset = 0
            num_lines = len(data)
            while offset < num_lines:
                line = data[offset]
                offset += 1
                if not line.startswith(DENY_DELIMITER):
                    fp.write(line)
                    continue
                else:
                    if offset == num_lines:
                        warn("DenyHosts comment line at end of file")
                        fp.write(line)
                        continue

                    timestamp = None
                    try:
                        rest = line.lstrip(DENY_DELIMITER)
                        timestamp, host_verify = rest.split(ENTRY_DELIMITER)
                        tm = time.strptime(timestamp)
                    except Exception as e:
                        warn("Parse error -- Ignorning timestamp: %s for: %s", timestamp, line)
                        warn("exception: %s", str(e))
                        # ignoring bad time string
                        fp.write(line)
                        continue

                    epoch = int(time.mktime(tm))
                    # print entry, epoch, self.cutoff

                    if self.cutoff > epoch:
                        # this entry should be purged
                        entry = data[offset]
                        if host_verify != entry:
                            warn("%s purge verification failed: %s vs. %s",
                                 self.deny_file,
                                 host_verify.rstrip(),
                                 entry.rstrip())

                            fp.write(line)
                            continue
                        host = parse_host(entry)
                        if host and host not in banned:
                            # purge
                            purged_hosts.append(host)

                            # increment offset past purged line
                            offset += 1
                        continue
                    else:
                        fp.write(line)
                        continue

            fp.close()
        except Exception as e:
            raise e
        return purged_hosts

#################################################################################


class PurgeIP(DenyFileUtilBase):
    def __init__(self, prefs, purgeip_list):
        deny_file = prefs.get('HOSTS_DENY')
        DenyFileUtilBase.__init__(self, deny_file, "purgeip")
        self.__prefs = prefs
        self.work_dir = prefs.get('WORK_DIR')
        self.purge_counter = PurgeCounter(prefs)
        self.__blocked_services = prefs.get('BLOCK_SERVICE')
        self.__purgeip_list = purgeip_list

    def run_purge(self):
        info("purging listed IP addresses.", )
        self.backup()

        # List of ips to purge
        purged_hosts = []
        blocked_hosts = self.get_data()
        for purgeip in self.__purgeip_list:
            purgeip_format = '{}: {}\n'.format(self.__blocked_services, purgeip)
            if purgeip_format in blocked_hosts:
                blocked_hosts.remove(purgeip_format)
                purged_hosts.append(purgeip)
        num_purged = len(purged_hosts)
        if num_purged > 0:
            self.create_temp(blocked_hosts)
            self.replace()
            abusive_hosts = AbusiveHosts(self.__prefs)
            abusive_hosts.purge_hosts(purged_hosts)
            abusive_hosts.save_abusive_hosts()
            self.purge_counter.increment(purged_hosts)
        else:
            self.remove_temp()

        info("num entries purged: %d", num_purged)
        plugin_purge = self.__prefs.get('PLUGIN_PURGE')
        if plugin_purge:
            plugin.execute(plugin_purge, purged_hosts)

        if num_purged > 0:
            return purged_hosts
        return None

    def create_temp(self, data_list):
        with open(self.temp_file, 'w') as tfh:
            tfh.writelines("{}\n".format(line) for line in data_list)
