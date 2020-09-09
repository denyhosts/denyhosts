import logging
import os

logger = logging.getLogger("firewalls")
debug = logger.debug
info = logger.info
error = logger.error
exception = logger.exception
warning = logger.warning


class IpTables(object):

    def __init__(self, prefs):
        self.__blockport = prefs.get("BLOCKPORT")
        self.__iptables = prefs.get("IPTABLES")

    def block_ips(self, ip_list):
        info("Creating new iptable rules for %s ips" % len(ip_list))
        try:
            for ip in ip_list:
                block_ip = str(ip)
                new_rule = self.__create_rule(block_ip)
                info("Creating new firewall rule %s", new_rule)
                os.system(new_rule)
        except Exception as e:
            msg = 'Unable to write new firewall rule with error: %s' % e
            print(msg)
            exception(msg)

    def __create_rule(self, block_ip):
        debug("Creating iptables rule for %s" % block_ip)
        if self.__blockport is not None and ',' in self.__blockport:
            rule = self.__create_multiport_rule(block_ip)
        elif self.__blockport:
            rule = self.__create_singleport_rule(block_ip)
        else:
            rule = self.__create_block_all_rule(block_ip)
        return '%s -I %s' % (self.__iptables, rule)

    def __create_singleport_rule(self, block_ip):
        debug("Generating INPUT block single port rule")
        sp_rule = "INPUT -p tcp --dport %s -s %s -j DROP" % \
                  (self.__blockport, block_ip)
        return sp_rule

    def __create_multiport_rule(self, block_ip):
        debug("Generating INPUT block multi-port rule")
        mp_rule = "INPUT -p tcp -m multiport --dports %s -s %s -j DROP" % \
                  (self.__blockport, block_ip)
        return mp_rule

    def __create_block_all_rule(self, block_ip):
        debug("Generating INPUT block all ports rule")
        ba_rule = "INPUT -s %s -j DROP" % (block_ip)
        return ba_rule

    def remove_ips(self, ip_list):
        info("Removing %s ips from iptables rules" % len(ip_list))
        try:
            for ip in ip_list:
                blocked_ip = str(ip)
                remove_rule = self.__remove_ip_rule(blocked_ip)
                info('Removing ip rule for %s' % blocked_ip)
                os.system(remove_rule)
        except Exception as e:
            msg = 'Unable to remove firewall rule with error: %s' % e
            print(msg)
            exception(msg)

    def __remove_ip_rule(self, blocked_ip):
        debug("Creating iptables remove rule for %s" % blocked_ip)
        if self.__blockport is not None and ',' in self.__blockport:
            rule = self.__create_multiport_rule(blocked_ip)
        elif self.__blockport:
            rule = self.__create_singleport_rule(blocked_ip)
        else:
            rule = self.__create_block_all_rule(blocked_ip)
        return '%s -D %s' % (self.__iptables, rule)
