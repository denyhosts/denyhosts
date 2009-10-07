import os
import logging
from constants import SECURE_LOG_OFFSET

debug = logging.getLogger("filetracker").debug

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

        debug("__get_last_offset():")
        debug("   first_line: %s", first_line)
        debug("   offset: %ld", offset)
            
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

        debug("__get_current_offset():")
        debug("   first_line: %s", first_line)
        debug("   offset: %ld", offset)
            
        return first_line, offset

    def update_first_line(self):
        first_line = ""
        try:
            fp = open(self.logfile, "r")
            first_line = fp.readline()[:-1]
        except Exception, e:
            raise e
        
        self.__first_line = first_line

    
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

        debug("get_offset():")        
        debug("   offset: %s", str(offset))
            
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

        
