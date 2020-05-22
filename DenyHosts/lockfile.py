import os
import sys
from .util import die


class LockFile(object):
    def __init__(self, lockpath):
        self.lockpath = lockpath
        self.fd = None

    def exists(self):
        return os.access(self.lockpath, os.F_OK)

    def get_pid(self):
        pid = ""
        try:
            with open(self.lockpath, "r") as fp:
                pid = fp.read().strip()
        except IOError:
            pass
        return pid

    def create(self):
        try:
            self.fd = os.open(self.lockpath,
                              os.O_CREAT |  # create file
                              os.O_TRUNC |  # truncate it, if it exists
                              os.O_WRONLY |  # write-only
                              os.O_EXCL,    # exclusive access
                              0o644)         # file mode

        except Exception as e:
            pid = self.get_pid()
            die("DenyHosts could not obtain lock (pid: %s)" % pid, e)

        s = "%s\n" % os.getpid()
        if sys.version_info < (3, 0):
            os.write(self.fd, s)
        else:
            os.write(self.fd, s.encode('UTF-8'))
        os.fsync(self.fd)

    def remove(self, die_=True):
        try:
            if self.fd:
                os.close(self.fd)
        except IOError:
            pass

        self.fd = None
        try:
            os.unlink(self.lockpath)
        except Exception as e:
            if die_:
                die("Error deleting DenyHosts lock file: %s" % self.lockpath, e)
