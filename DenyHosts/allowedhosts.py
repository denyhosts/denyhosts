import logging
import os
from socket import getfqdn, gethostbyname

from .constants import ALLOWED_HOSTS, ALLOWED_WARNED_HOSTS
from .regex import ALLOWED_REGEX
from .util import is_true

logger = logging.getLogger("AllowedHosts")
debug, warn = logger.debug, logger.warning


class AllowedHosts(object):
    def __init__(self, prefs):
        debug("initializing AllowedHosts")
        work_dir = prefs.get("WORK_DIR")
        self.hostname_lookup = is_true(prefs.get("ALLOWED_HOSTS_HOSTNAME_LOOKUP"))
        self.allowed_path = os.path.join(work_dir, ALLOWED_HOSTS)
        self.warned_path = os.path.join(work_dir, ALLOWED_WARNED_HOSTS)
        self.allowed_hosts = {}
        self.warned_hosts = {}
        self.new_warned_hosts = []
        self.load_hosts()
        self.load_warned_hosts()
        debug("done initializing AllowedHosts")

    def __contains__(self, ip_addr):
        if ip_addr in self.allowed_hosts:
            return 1
        return 0

    def dump(self):
        print("Dumping AllowedHosts")
        print(list(self.allowed_hosts.keys()))

    def load_hosts(self):
        try:
            fp = open(self.allowed_path, "r")
        except Exception as e:
            debug("Could not open %s - %s", self.allowed_path, str(e))
            return

        for line in fp:
            line = line.strip()
            if not line or line[0] == '#':
                continue

            m = ALLOWED_REGEX.match(line)
            debug("line: %s - regex match?   %s", line, m is not None)
            if m:
                # line contains an ip address
                first3 = m.group('first_3bits')
                fourth = m.group('fourth')
                wildcard = m.group('ip_wildcard')
                ip_range = m.group('ip_range')

                if fourth:
                    self.allowed_hosts["%s%s" % (first3, fourth)] = 1
                    self.add_hostname("%s%s" % (first3, fourth))
                elif wildcard:
                    for i in range(256):
                        self.allowed_hosts["%s%s" % (first3, i)] = 1
                        self.add_hostname("%s%s" % (first3, i))
                else:
                    start, end = ip_range.split("-")
                    for i in range(int(start), int(end)):
                        self.allowed_hosts["%s%d" % (first3, i)] = 1
                        self.add_hostname("%s%s" % (first3, i))
            else:
                # assume that line contains hostname
                self.allowed_hosts[line] = 1
                try:
                    # lookup ip address of host
                    ip = gethostbyname(line)
                    self.allowed_hosts[ip] = 1
                except Exception:
                    pass

        fp.close()
        debug("allowed_hosts: %s", list(self.allowed_hosts.keys()))

    def add_hostname(self, ip_addr):
        if not self.hostname_lookup:
            return
        else:
            hostname = getfqdn(ip_addr)
            if hostname != ip_addr:
                self.allowed_hosts[hostname] = 1

    def add_warned_host(self, host):
        # debug("warned_hosts: %s", self.warned_hosts.keys())

        if host not in self.warned_hosts:
            debug("%s not in warned hosts" % host)
            self.new_warned_hosts.append(host)
            self.warned_hosts[host] = None

    def get_new_warned_hosts(self):
        return self.new_warned_hosts

    def load_warned_hosts(self):
        try:
            if os.path.isfile(self.warned_path):
                with open(self.warned_path, "r") as fp:
                    for line in fp:
                        self.warned_hosts[line.strip()] = None
        except IOError:
            warn("Couldn't load warned hosts from %s" % self.warned_path)

    def save_warned_hosts(self):
        if not self.new_warned_hosts:
            return
        try:
            with open(self.warned_path, "a") as fp:
                for host in self.new_warned_hosts:
                    fp.write("%s\n" % host)
        except Exception as e:
            print(e)

    def clear_warned_hosts(self):
        self.new_warned_hosts = []
