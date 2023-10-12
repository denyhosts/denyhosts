#!/usr/bin/env python3
import os
import platform
import sys
import logging
import argparse


currentVersion = sys.version_info.major    
currentVersion += sys.version_info.minor  / 10.

if currentVersion < 3.6:
    raise Exception("It requires minimal Python 3.6 to run")

sys.path.insert(0, '/usr/share/denyhosts')

import DenyHosts.python_version

import getopt
from getopt import GetoptError
import traceback

from DenyHosts.util import die, setup_logging, is_true
from DenyHosts.lockfile import LockFile
from DenyHosts.prefs import Prefs
from DenyHosts.version import VERSION
from DenyHosts.deny_hosts import DenyHosts
from DenyHosts.denyfileutil import Purge, PurgeIP, Migrate, UpgradeTo099
from DenyHosts.firewalls import IpTables
from DenyHosts.constants import *
from DenyHosts.sync import Sync

logging.basicConfig()
logger = logging.getLogger('denyhosts')
info = logger.info
debug = logger.debug
#################################################################################

if __name__ == '__main__':
    logfiles = []
    purgeip_list = []
    config_file = CONFIG_FILE
    ignore_offset = 0
    noemail = 0
    verbose = 0
    migrate = 0
    purge = 0
    purge_all = 0
    sync_mode = 0
    daemon = 0
    foreground = 0
    enable_debug = 0
    purgeip = 0
    upgrade099 = 0
    unlock = 0
    args = sys.argv[1:]

    parser = argparse.ArgumentParser(description='',
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog='Note: multiple --file args can be processed.\n' + \
                                     'If multiple files are provided, --ignore is implied\n\n' + \
                                     'Note: multiple --purgeip arguments can be processed.\n\n' + \
                                     'When run in --daemon mode the following flags are ignored:\n' + \
                                     '     --file, --purge, --purge-all, --purgeip, --migrate, --sync, --verbose')

    parser.add_argument('-c', '--config', metavar='config', help='The pathname of the configuration file')
    parser.add_argument('-f', '--file', metavar='file', help='The name of log file to parse')
    parser.add_argument('-i', '--ignore', action='store_true', help='Ignore last processed offset (start processing from beginning')
    parser.add_argument('-n', '--noemail', action='store_true', help='Do not send an email report')
    parser.add_argument('-s', '--unlock', action='store_true', help='if lockfile exists, remove it and run as normal')
    parser.add_argument('-m', '--migrate', action='store_true', help='migrate your HOSTS_DENY file so that it is suitable for --purge')
    parser.add_argument('-p', '--purge', action='store_true', help='expire entries older than your PURGE_DENY setting')
    parser.add_argument('--purge-all', action='store_true', help='expire all entries')
    parser.add_argument('--purgeip', metavar='purgeip', help='expire designated IP entry immediately')
    parser.add_argument('--daemon', action='store_true', help='run DenyHosts in daemon mode')
    parser.add_argument('--foreground', action='store_true', help='run DenyHosts in foreground mode')
    parser.add_argument('--sync', action='store_true', help='run DenyHosts synchronization mode')
    parser.add_argument('-v', '--version', action='store_true',  help='Prints the version of DenyHosts and exits')
    parser.add_argument('-d', '--debug', action='store_true', help='debug mode activated')
    parser.add_argument('--upgrade099', action='store_true', help='')
    parser.add_argument('--verbose', action='store_true', help='')

    args = parser.parse_args()
    print(args)


    config_file = args.config
    if args.version:
        print("DenyHosts version:", VERSION)
        sys.exit(0)
    if args.file: logfiles.append(args.file)
    if args.ignore: ignore_offset = 1
    if args.noemail: noemail = 1
    if args.verbose: verbose = 1
    if args.debug: enable_debug = 1
    if args.migrate: migrate = 1
    if args.purge: purge = 1
    if args.sync: sync_mode = 1
    if args.unlock: unlock = 1
    if args.foreground: foreground = 1
    if purge_all: purge_all = 1
    if args.purgeip:
        purgeip_list = args.purgeip
        purgeip = 1
    if args.upgrade099: upgrade099 = 1


    # This is generally expected to be in the environment, but there's no
    # non-hackish way to get systemd to set it, so just hack it in here.
    os.environ['HOSTNAME'] = platform.node()

    prefs = Prefs(config_file)
    iptables = prefs.get('IPTABLES')

    if prefs.get('SYNC_SERVER'):
        try:
            sync = Sync(prefs)
            sync.send_release_used(VERSION)
            del sync
        except:
            # more than likely sync server doesn't have the option yet
            pass

    first_time = 0
    try:
        if not os.path.exists(prefs.get('WORK_DIR')):
            os.makedirs(prefs.get('WORK_DIR'))
            first_time = 1
    except Exception as e:
        if e[0] != 17:
            print(e)
            sys.exit(1)

    # On some operating systems the file /etc/hosts.deny (or
    # whatever HOSTS_DENY is set to, may not exist. We should
    # "touch" the file to make sure it is there to avoid errors later.
    try:
        host_filename = prefs.get("HOSTS_DENY")
        if host_filename:
            fp = open(prefs.get("HOSTS_DENY"), "a")
            fp.close()
    except Exception as e:
        print("Unable to create file specified by HOSTS_DENY variable.")

    setup_logging(prefs, enable_debug, verbose, daemon)

    # we will only sync to the server if the sync server is enabled and the sync_version is either true or commented out
    # config file has it set to sync the version by default if the sync server is enabled
    if prefs.get('SYNC_SERVER') and (prefs.get('SYNC_VERSION') is None or is_true(prefs.get('SYNC_VERSION'))):
        debug('Attempting to Sync Version: %s' % VERSION)
        try:
            sync = Sync(prefs)
            sync.send_release_used(VERSION)
            del sync
        except:
            # more than likely sync server doesn't have the option yet
            pass

    if not logfiles or daemon:
        logfiles = [prefs.get('SECURE_LOG')]
    elif len(logfiles) > 1:
        ignore_offset = 1

    if not prefs.get('ADMIN_EMAIL'):
        noemail = 1

    lock_file = LockFile(prefs.get('LOCK_FILE'))

    if unlock:
        if os.path.isfile(prefs.get('LOCK_FILE')):
            lock_file.remove()

    lock_file.create()

    if upgrade099 and not (daemon or foreground):
        if not prefs.get('PURGE_DENY'):
            lock_file.remove()
            die(
                "You have supplied the --upgrade099 flag," +
                " however you have not set PURGE_DENY in your configuration file"
            )
        else:
            u = UpgradeTo099(prefs.get("HOSTS_DENY"))

    if migrate and not (daemon or foreground):
        if not prefs.get('PURGE_DENY'):
            lock_file.remove()
            die("You have supplied the --migrate flag however you have not set PURGE_DENY in your configuration file.")
        else:
            m = Migrate(prefs.get("HOSTS_DENY"))

    if purgeip or purge or purge_all:
        removed_hosts = None
        # clear out specific IP addresses
        if purgeip and not daemon:
            if len(purgeip_list) < 1:
                lock_file.remove()
                die("You have provided the --purgeip flag however you have not listed any IP addresses to purge.")
            else:
                try:
                    ip_purger = PurgeIP(prefs, purgeip_list)
                    removed_hosts = ip_purger.run_purge()
                except Exception as e:
                    lock_file.remove()
                    die(str(e))

        # Try to purge old records without any delay
        if purge_all and not daemon:
            purge_time = 1
            try:
                purger = Purge(prefs, purge_time)
                removed_hosts = purger.run_purge()
            except Exception as e:
                lock_file.remove()
                die(str(e))

        if purge and not (daemon or foreground):
            purge_time = prefs.get('PURGE_DENY')
            if not purge_time:
                lock_file.remove()
                die("You have provided the --purge flag however you have not set PURGE_DENY in your configuration file.")
            else:
                try:
                    purger = Purge(prefs, purge_time)
                    removed_hosts = purger.run_purge()
                except Exception as e:
                    lock_file.remove()
                    die(str(e))

        if iptables and removed_hosts:
            firewall_iptables = IpTables(prefs)
            firewall_iptables.remove_ips(removed_hosts)

    try:
        for f in logfiles:
            dh = DenyHosts(f, prefs, lock_file, ignore_offset,
                           first_time, noemail, daemon, foreground)
    except KeyboardInterrupt:
        pass
    except SystemExit as e:
        pass
    except Exception as e:
        traceback.print_exc(file=sys.stdout)
        print("\nDenyHosts exited abnormally")

    if sync_mode and not (daemon or foreground):
        if not prefs.get('SYNC_SERVER'):
            lock_file.remove()
            die("You have provided the --sync flag however your configuration file is missing a value for SYNC_SERVER.")
        sync_upload = is_true(prefs.get("SYNC_UPLOAD"))
        sync_download = is_true(prefs.get("SYNC_DOWNLOAD"))
        if not sync_upload and not sync_download:
            lock_file.remove()
            die(
                "You have provided the --sync flag"
                " however your configuration file has SYNC_UPLOAD and SYNC_DOWNLOAD set to false."
            )
        try:
            sync = Sync(prefs)
            if sync_upload:
                timestamp = sync.send_new_hosts()
            if sync_download:
                new_hosts = sync.receive_new_hosts()
                if new_hosts:
                    # Logging the newly received hosts
                    info("Received new hosts: %s", str(new_hosts))
                    dh.get_denied_hosts()
                    dh.update_hosts_deny(new_hosts)
            sync.xmlrpc_disconnect()
        except Exception as e:
            lock_file.remove()
            die("Error synchronizing data", e)

    # remove lock file on exit
    lock_file.remove()
