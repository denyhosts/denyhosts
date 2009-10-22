import os
from socket import getfqdn, gethostbyname
import logging


from constants import ALLOWED_HOSTS, ALLOWED_WARNED_HOSTS
from regex import ALLOWED_REGEX_MASK, IP_REGEX
from util import is_true

debug = logging.getLogger("AllowedHosts").debug

HIGH_BIT_MASK = 0x80000000

class IPTrie:
    def __init__(self):
        self.root = {'flag': False, 'left': None, 'right': None}

    def __repr__(self):
        return repr(self.root)
    
    def insert(self, ip_address, mask_length):
        int_address = to_int(ip_address)
        current = self.root
        for i in range(31, 31 - mask_length, -1):
            if current['flag'] == True:
                return
            bit = (int_address & HIGH_BIT_MASK) >> 31
            int_address <<= 1
            if bit == 0:
                if current['left'] == None:
                    current['left'] = {'flag': False, 'left': None, 'right': None}
                current = current['left']
            else:
                if current['right'] == None:
                    current['right'] = {'flag': False, 'left': None, 'right': None}
                current = current['right']
        current['flag'] = True

    def __contains__(self, ip_address):
        int_address = to_int(ip_address)
        current = self.root
        while True:
            if current['flag']:
                return True
            bit = (int_address & HIGH_BIT_MASK) >> 31
            int_address <<= 1
            if bit == 0:
                current = current['left']
            else:
                current = current['right']
            if current == None:
                return False

def to_int(ip_address):
    m = IP_REGEX.match(ip_address)
    if not m:
        raise ValueError("malformed IP address: %s" % ip_address)
    return (int(m.group("octet1")) * 2 ** 24 +
        int(m.group("octet2")) * 2 ** 16 +
        int(m.group("octet3")) * 2 ** 8 +
        int(m.group("octet4")))

class AllowedHosts:
    def __init__(self, prefs):
        debug("initializing AllowedHosts")
        work_dir = prefs.get("WORK_DIR")
        self.hostname_lookup = is_true(prefs.get("ALLOWED_HOSTS_HOSTNAME_LOOKUP"))
        self.allowed_path = os.path.join(work_dir, ALLOWED_HOSTS)
        self.warned_path = os.path.join(work_dir, ALLOWED_WARNED_HOSTS)
        self.allowed_hosts = IPTrie()
        self.warned_hosts = {}
        self.new_warned_hosts = []
        self.load_hosts()
        self.load_warned_hosts()
        debug("done initializing AllowedHosts")

    def __contains__(self, ip_addr):
        if self.allowed_hosts.__contains__(ip_addr): return 1
        else: return 0

    def dump(self):
        print "Dumping AllowedHosts"
        print self.allowed_hosts.__repr__()

        
    def load_hosts(self):
        try:
            fp = open(self.allowed_path, "r")
        except Exception, e:
            debug("Could not open %s - %s", self.allowed_path, str(e))
            return

        for line in fp:
            line = line.strip()
            if not line or line[0] == '#': continue
            m = ALLOWED_REGEX_MASK.match(line)
            debug("line: %s - regex match?   %s", line, m != None)
            if m:
                ip = m.group("ip")
                long_mask = m.group("long_mask")
                short_mask = m.group("short_mask")
                mask_bits = 0
                if short_mask:
                    mask_bits = int(short_mask)
                else:
                    if long_mask:
                        HIGH_BIT_MASK = 0x80000000
                        mask = to_int(long_mask)
                        # TODO: Be more clever about this
                        bit = (mask & HIGH_BIT_MASK) >> 31
                        while bit == 1:
                            mask_bits += 1
                            mask <<= 1
                            bit = (mask & HIGH_BIT_MASK) >> 31
                    else:
                        # Not specifying a subnet mask matches entire IP address
                        mask_bits = 32
                        trie.insert(ip, mask_bits)
            else:
                # assume that line contains hostname
                self.allowed_hosts[line] = 1
                try:
                    # lookup ip address of host
                    ip = gethostbyname(line)
                    self.allowed_hosts[ip] = 1
                except:
                    pass
        fp.close()
        debug("allowed_hosts: %s", self.allowed_hosts.root)


    def add_hostname(self, ip_addr):
        if not self.hostname_lookup:
            return
        else:
            hostname = getfqdn(ip_addr)
            if hostname != ip_addr:
                self.allowed_hosts[hostname] = 1


    def add_warned_host(self, host):
        #debug("warned_hosts: %s", self.warned_hosts.keys())

        if host not in self.warned_hosts:
            debug("%s not in warned hosts" % host)
            self.new_warned_hosts.append(host)
            self.warned_hosts[host] = None

            
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


    def clear_warned_hosts(self):
        self.new_warned_hosts = []

