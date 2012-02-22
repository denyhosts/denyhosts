import os
from socket import getfqdn, gethostbyname, herror
import logging
from pprint import pprint

from constants import ALLOWED_HOSTS, ALLOWED_WARNED_HOSTS
from regex import ALLOWED_REGEX_MASK, IP_REGEX
from util import is_true

logger = logging.getLogger("AllowedHosts")
debug, warn = logger.debug, logger.warn

HIGH_BIT_MASK = 0x80000000

class IPTrie:
    def __init__(self):
        self.root = {'flag': False, 'left': None, 'right': None}

    def __str__(self):
        return repr(self.root)

    def insert(self, ip_address, mask_length):
        int_address = to_int(ip_address)
        current = self.root
        for i in xrange(mask_length):
            if current['flag']:
                return
            bit = (int_address & HIGH_BIT_MASK) >> 31
            int_address <<= 1
            if not bit:
                if current['left'] is None:
                    current['left'] = {'flag': False, 'left': None, 'right': None}
                current = current['left']
            else:
                if current['right'] is None:
                    current['right'] = {'flag': False, 'left': None, 'right': None}
                current = current['right']
        current['flag'] = True

    def __contains__(self, ip_address):
        try:
            int_address = to_int(ip_address)
        except ValueError:
            # Probably a hostname.
            return False
        current = self.root
        while True:
            if current['flag']:
                return True
            bit = (int_address & HIGH_BIT_MASK) >> 31
            int_address <<= 1
            if not bit:
                current = current['left']
            else:
                current = current['right']
            if current is None:
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
        self.allowed_ips = IPTrie()
        self.allowed_hostnames = set()
        self.warned_hosts = set()
        self.new_warned_hosts = []
        self.load_hosts()
        self.load_warned_hosts()
        debug("done initializing AllowedHosts")

    def __contains__(self, ip_or_hostname):
        if ip_or_hostname in self.allowed_ips or ip_or_hostname in self.allowed_hostnames:
            return True
        if self.hostname_lookup:
            pass
        return (ip_or_hostname in self.allowed_ips or
                (self.hostname_lookup and ip_or_hostname in self.allowed_hostnames))

    def dump(self):
        print "Dumping AllowedHosts"
        pprint(self.allowed_ips.root)

    def load_hosts(self):
        try:
            fp = open(self.allowed_path, "r")
        except Exception, e:
            debug("Could not open %s - %s", self.allowed_path, str(e))
            return

        for line in fp:
            line = line.strip()
            if not line or line[0] == '#':
                continue
            m = ALLOWED_REGEX_MASK.match(line)
            debug("line: %s - regex match?   %s", line, m is not None)
            if m:
                ip = m.group("ip")
                long_mask = m.group("long_mask")
                short_mask = m.group("short_mask")
                mask_bits = 0
                if short_mask:
                    mask_bits = int(short_mask)
                else:
                    if long_mask:
                        mask = to_int(long_mask)
                        bit = (mask & HIGH_BIT_MASK) >> 31
                        while bit == 1:
                            mask_bits += 1
                            mask <<= 1
                            bit = (mask & HIGH_BIT_MASK) >> 31
                    else:
                        # Not specifying a subnet mask matches entire IP address
                        mask_bits = 32
                self.allowed_ips.insert(ip, mask_bits)
            else:
                # assume that line contains hostname
                self.allowed_hostnames.add(line)
                if self.hostname_lookup:
                    try:
                        # lookup ip address of host
                        ip = gethostbyname(line)
                        self.allowed_ips.insert(ip, 32)
                    except herror:
                        pass
        fp.close()
        debug("allowed_hosts: %s", self.allowed_ips.root)

    # TODO: Fix this
    def add_hostname(self, hostname):
        if not self.hostname_lookup:
            return
        else:
            hostname = getfqdn(hostname)
            if hostname != hostname:
                self.allowed_hostnames.add(hostname)

    def add_warned_host(self, host):
        #debug("warned_hosts: %s", self.warned_hosts.keys())

        if host not in self.warned_hosts:
            debug("%s not in warned hosts" % host)
            self.new_warned_hosts.append(host)
            self.warned_hosts.add(host)

    def get_new_warned_hosts(self):
        return self.new_warned_hosts

    def load_warned_hosts(self):
        try:
            fp = open(self.warned_path, "r")
            for line in fp:
                self.warned_hosts.add(line.strip())
            fp.close()
        except IOError:
            warn("Couldn't load warned hosts from %s" % self.warned_path)

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
