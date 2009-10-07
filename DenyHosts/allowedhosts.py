import os

from constants import ALLOWED_HOSTS, ALLOWED_WARNED_HOSTS

from regex import ALLOWED_REGEX

class AllowedHosts:
    def __init__(self, work_dir):
        self.allowed_path = os.path.join(work_dir, ALLOWED_HOSTS)
        self.warned_path = os.path.join(work_dir, ALLOWED_WARNED_HOSTS)
        self.allowed_hosts = {}
        self.warned_hosts = {}
        self.new_warned_hosts = []
        self.load_hosts()
        self.load_warned_hosts()

    def __contains__(self, ip_addr):
        if self.allowed_hosts.has_key(ip_addr): return 1
        else: return 0

    def dump(self):
        print "Dumping AllowedHosts"
        print self.allowed_hosts.keys()

        
    def load_hosts(self):
        try:
            fp = open(self.allowed_path, "r")
        except:
            return

        for line in fp:
            line = line.strip()
            if not line or line[0] == '#': continue

            m = ALLOWED_REGEX.match(line)
            if m:
                first3 = m.group('first_3bits')
                fourth = m.group('fourth')
                wildcard = m.group('ip_wildcard')
                ip_range = m.group('ip_range')

                if fourth:
                    self.allowed_hosts["%s%s" % (first3, fourth)] = 1
                elif wildcard:
                    for i in range(256):
                        self.allowed_hosts["%s%s" % (first3, i)] = 1
                else:
                    start, end = ip_range.split("-")
                    for i in range(int(start), int(end)):
                        self.allowed_hosts["%s%d" % (first3, i)] = 1
            
        fp.close()

    def add_warned_host(self, host):
        if host not in self.warned_hosts:
            self.new_warned_hosts.append(host)
            
    def get_new_warned_hosts(self):
        return self.new_warned_hosts
    

    def load_warned_hosts(self):
        try:
            fp = open(self.warned_path, "r")
            for line in fp:
                self.warned_hosts[line.strip()] = None
            fp.close()
        except:
            pass


    def save_warned_hosts(self):
        if not self.new_warned_hosts: return
        try:
            fp = open(self.warned_path, "a")
            for host in self.new_warned_hosts:
                fp.write("%s\n" % host)
            fp.close()
        except Exception, e:
            print e
