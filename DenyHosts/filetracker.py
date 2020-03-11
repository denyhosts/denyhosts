import os
import logging
from .constants import SECURE_LOG_OFFSET

debug = logging.getLogger("filetracker").debug


class FileTracker(object):
    def __init__(self, work_dir, logfile):
        self.work_dir = work_dir
        self.logfile = logfile
        (self.__first_line, self.__offset) = self.__get_current_offset()

    def __get_last_offset(self):
        path = os.path.join(self.work_dir, SECURE_LOG_OFFSET)
        first_line = ""
        offset = 0
        try:
            with open(path, 'r') as fp:
                first_line = fp.readline()[:-1]
                offset_line = fp.readline()
                if offset_line is None or offset_line == '':
                    offset = 0
                else:
                    offset = int(offset_line)
        except IOError:
            pass

        debug("__get_last_offset():")
        debug("   first_line: %s", first_line)
        debug("   offset: %ld", offset)

        return first_line, offset

    def __get_current_offset(self):
        try:
            with open(self.logfile, 'r') as fp:
                first_line = fp.readline()[:-1]
                fp.seek(0, 2)
                offset = fp.tell()
        except IOError as e:
            raise e

        debug("__get_current_offset():")
        debug("   first_line: %s", first_line)
        debug("   offset: %ld", offset)

        return first_line, offset

    def update_first_line(self):
        try:
            fp = open(self.logfile, "r")
            first_line = fp.readline()[:-1]
        except IOError as e:
            raise e
        finally:
            fp.close()

        self.__first_line = first_line

    def get_offset(self):
        last_line, last_offset = self.__get_last_offset()
        if last_line != self.__first_line:
            # log file was rotated, start from beginning
            offset = 0
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
        path = os.path.join(self.work_dir, SECURE_LOG_OFFSET)
        try:
            with open(path, "w") as fp:
                fp.writelines([
                    "%s\n" % self.__first_line,
                    "%ld\n" % offset
                ])
        except IOError:
            print("Could not save logfile offset to: %s" % path)
