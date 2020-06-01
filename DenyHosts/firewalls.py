import logging
import os
import subprocess

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
        ba_rule = "INPUT -s %s -j DROP" % block_ip
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
        return '%s -D %s ' % (self.__iptables, rule)

    def add_ipset_drop_groups(self, ipset_group):
        iptables_groups = ['INPUT', 'FORWARD']
        for iptable_group in iptables_groups:
            ipset_rule = self.__create_ipset_rule(iptable_group, ipset_group)
            try:
                os.system('%s -I %s' % (self.__iptables, ipset_rule))
            except Exception as e:
                exception('Error creating ipset group in iptables for %s: %s' % (iptable_group, e))

    def __create_ipset_rule(self, iptables_group, ipset_group):
        debug("Creating iptables rule for %s" % iptables_group, ipset_group)
        if self.__blockport is not None and ',' in self.__blockport:
            rule = self.__create_multiport_rule(iptables_group, ipset_group)
        elif self.__blockport:
            rule = self.__create_singleport_rule(iptables_group, ipset_group)
        else:
            rule = self.__create_block_all_rule(iptables_group, ipset_group)
        return rule

    def __create_singleport_ipset_rule(self, iptables_group, ipset_group):
        debug("Generating Ipset %s block single port rule" % iptables_group)
        sp_rule = "%s -p tcp --dport %s -m set --match-set %s src -j DROP" % \
                  (self.__iptables, iptables_group, self.__blockport, ipset_group)
        return sp_rule

    def __create_multiport_ipset_rule(self, iptables_group, ipset_group):
        debug("Generating Ipset %s block multi-port rule" % iptables_group)
        mp_rule = "%s -p tcp -m multiport --dports %s -m set --match-set %s src -j DROP" % \
                  (self.__iptables, iptables_group, self.__blockport, ipset_group)
        return mp_rule

    def __create_block_all_ipset_rule(self, iptables_group, ipset_group):
        debug("Generating Ipset %s block all ports rule" % iptables_group)
        ba_rule = "%s -m set --match-set %s src -j DROP" % \
                  (self.__iptables, iptables_group, ipset_group)
        return ba_rule

    def does_ipset_group_exist(self):
        ipset_group = self.get('IPSET_NAME')
        ipset_rule = self.__create_ipset_rule('INPUT', ipset_group)
        try:
            subprocess.check_output([self.__iptables, '-C', ipset_rule])
        except Exception as e:
            # if it doesn't exist an error occurs
            exception('IPSET group %s, does not exist: %s' % (ipset_group, e))
            return False
        return True


class IpSet(object):

    def __init__(self, prefs):
        self.prefs = prefs
        self.blacklist = prefs.get('IPSET_NAME')

    def initial_setup(self):
        if not self.does_blacklist_exist():
            try:
                subprocess.check_output(['ipset', 'add', self.blacklist, 'hash:ip', 'hashsize', '4096'])
                debug('%s ipset group created' % self.blacklist)
            except subprocess.CalledProcessError:
                error('Unable to create the ipset group: %s' % self.blacklist)
        iptables = IpTables(self.prefs)

        if not iptables.does_ipset_group_exist():
            iptables.add_ipset_drop_groups(self.blacklist)

    def does_blacklist_exist(self):
        try:
            subprocess.check_output(['ipset', 'list', self.blacklist])
        except subprocess.CalledProcessError:
            debug('%s does not exist in ipset' % self.blacklist)
            return False
        return True

    def add_to_blacklist(self, block_ip):
        try:
            subprocess.check_output(['ipset', 'add', self.blacklist, block_ip])
        except subprocess.CalledProcessError:
            exception('Unable to add %s to ipset group %s' % (block_ip, self.blacklist))
            return False
        return True

    def remove_from_blacklist(self, blocked_ip):
        try:
            subprocess.check_output(['ipset', 'del', self.blacklist, blocked_ip])
        except subprocess.CalledProcessError:
            exception('Unable to remove %s from ipset group %s' % (blocked_ip, self.blacklist))
            return False
        return True

    def purge_full_blacklist(self):
        try:
            subprocess.check_output(['ipset', 'flush', self.blacklist])
        except subprocess.CalledProcessError:
            exception('Unable to flush the ipset group %s' % self.blacklist)
            return False
        return True

    def is_ip_in_blacklist(self, blocked_ip):
        try:
            subprocess.check_output(['ipset', 'test', self.blacklist, blocked_ip])
        except subprocess.CalledProcessError:
            debug('%s does not exist in ipset group %s' % (blocked_ip, self.blacklist))
            return False
        return True

    def save_blacklist(self, output_file):
        try:
            subprocess.check_output(['ipset', 'save', self.blacklist, '-f', output_file])
        except subprocess.CalledProcessError:
            debug('Unable to save ipset rules for %s to the backup file %s' % (self.blacklist, output_file))
            return False
        return True

    def restore_blacklist(self, restore_file):
        try:
            subprocess.check_output(['ipset', 'restore', '-f', restore_file])
        except subprocess.CalledProcessError:
            debug('Unable to restore ipset rules for %s from the backup file %s' % (self.blacklist, restore_file))
            return False
        return True
