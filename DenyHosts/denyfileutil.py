import os
import shutil
import time
import logging

from constants import TAB_OFFSET, PURGE_TIME_LOOKUP, DENY_DELIMITER
from regex import PURGE_TIME_REGEX
from loginattempt import AbusiveHosts
from util import parse_host

debug = logging.getLogger("denyfileutil").debug
info = logging.getLogger("denyfileutil").info
warn = logging.getLogger("denyfileutil").warn

class DenyFileUtilBase:
    def __init__(self, deny_file, extra_file_id=""):
        self.deny_file = deny_file
        self.backup_file = "%s.%s.bak" % (deny_file, extra_file_id)
        self.temp_file = "%s.%s.tmp" % (deny_file, extra_file_id)
        
    def backup(self):
        try:
            shutil.copy(self.deny_file, self.backup_file)
        except Exception, e:
            warn(str(e))

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
    def __init__(self, deny_file, purge_timestr, work_dir):
        DenyFileUtilBase.__init__(self, deny_file, "purge")
        cutoff = self.calculate(purge_timestr)

        self.cutoff = long(time.time()) - cutoff
        debug("relative cutoff: %ld (seconds)", cutoff)
        debug("absolute cutoff: %ld (epoch)", self.cutoff)
        info("purging entries older than: %s",
             time.asctime(time.localtime(self.cutoff)))
        
        self.backup()

        purged_hosts = self.create_temp(self.get_data())
        num_purged = len(purged_hosts)
        if num_purged > 0:
            self.replace()
            abusive_hosts = AbusiveHosts(work_dir)
            abusive_hosts.purge_hosts(purged_hosts)
            abusive_hosts.save_abusive_hosts()
        else:
            self.remove_temp()
            
        info("num entries purged: %d", num_purged)
              
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
        purged_hosts = []
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
                    warn("Parse error -- Ignorning timestamp: %s", timestamp)
                    # ignoring bad time string
                    fp.write(line)
                    continue

                epoch = long(time.mktime(tm))
                #print entry, epoch, self.cutoff

                if self.cutoff > epoch:
                    host = parse_host(entry)
                    if host:
                        purged_hosts.append(host)
                    continue
                else:
                    fp.write(line)
                    continue
            fp.close()
        except Exception, e:
            raise e

        return purged_hosts
    
