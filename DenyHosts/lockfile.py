import os
from util import die

class LockFile:
    def __init__(self, lockpath):
        self.lockpath = lockpath
        self.fd = None

    def exists(self):
        return os.access(self.lockpath, os.F_OK)


    def get_pid(self):
        pid = ""
        try:
            fp = open(self.lockpath, "r")
            pid = fp.read().strip()
            fp.close()            
        except:
            pass
        return pid


    def create(self):
        try:
            self.fd = os.open(self.lockpath,
                              os.O_CREAT |  # create file
                              os.O_TRUNC |  # truncate it, if it exists
                              os.O_WRONLY | # write-only
                              os.O_EXCL,    # exclusive access
                              0644)         # file mode

        except Exception, e:
            pid = self.get_pid()
            die("DenyHosts could not obtain lock (pid: %s)" % pid, e)
            
        os.write(self.fd, "%s\n" % os.getpid())
        os.fsync(self.fd)


    def remove(self, die_=True):
        try:
            if self.fd: os.close(self.fd)
        except:
            pass
        
        self.fd = None
        try:
            os.unlink(self.lockpath)
        except Exception, e:
            if die_:
                die("Error deleting DenyHosts lock file: %s" % self.lockpath, e)
