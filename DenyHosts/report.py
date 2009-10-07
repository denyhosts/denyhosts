import os
import re
import socket
from types import ListType, TupleType
import logging
from util import is_true
try:
    import syslog
    HAS_SYSLOG = True
except:
    HAS_SYSLOG = False

debug = logging.getLogger("report").debug
warn = logging.getLogger("report").warn

IP_ADDR_REGEX = re.compile(r"""(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""")

class Report:
    def __init__(self, hostname_lookup, use_syslog=False):
        self.report = ""
        if (use_syslog and not HAS_SYSLOG):
            warn("syslog is unavailable on this platform")
        self.use_syslog = use_syslog and HAS_SYSLOG
        if self.use_syslog:
            syslog.openlog("denyhosts")
        self.hostname_lookup = is_true(hostname_lookup)
        
    def empty(self):
        if self.report: return 0
        else: return 1

    def clear(self):
        self.report = ""
    
    def get_report(self):
        return self.report
    
    def add_section(self, message, iterable):
        self.report += "%s:\n\n" % message
        for i in iterable:
            if type(i) in (TupleType, ListType):
                extra = ": %d\n" % i[1]
                i = i[0]
            else:
                extra = ""
            if self.hostname_lookup:
                hostname = self.get_hostname(i)
                debug("get_host: %s", hostname)
            else: hostname = i

            self.report += "%s%s\n" % (hostname, extra)
            
            if self.use_syslog:
                syslog.syslog("%s - %s%s" %(message, hostname, extra))
        self.report += "\n" + "-" * 70 + "\n"

        
    def get_hostname(self, text):
        m = IP_ADDR_REGEX.search(text)

        if m:
            start = m.start()
            ip = m.group('ip')
            text = text[:start]
        else:
            return text

        hostname = socket.getfqdn(ip)
        if hostname == ip:
            hostname = "unknown"
        return "%s (%s)" % (ip, hostname)

           
        
