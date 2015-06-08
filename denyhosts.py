#!/usr/bin/env python
import os
import platform
import sys
import logging
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
from DenyHosts.constants import *
from DenyHosts.sync import Sync

info = logging.getLogger("denyhosts").info
#################################################################################

def usage():
    print("Usage:")
    print("%s [-f logfile | --file=logfile] [ -c configfile | --config=configfile] [-i | --ignore] [-n | --noemail] [--purge] [--purge-all] [--purgeip=ip] [--migrate] [--daemon] [--sync] [--version]" % sys.argv[0])
    print("\n\n")
    print(" --config: The pathname of the configuration file")
    print(" --file:   The name of log file to parse")
    print(" --ignore: Ignore last processed offset (start processing from beginning)")
    print(" --noemail: Do not send an email report")
    print(" --unlock: if lockfile exists, remove it and run as normal")
    print(" --migrate: migrate your HOSTS_DENY file so that it is suitable for --purge")
    print(" --purge: expire entries older than your PURGE_DENY setting")
    print(" --purge-all: expire all entries")
    print(" --purgeip: expire designated IP entry immediately")
    print(" --daemon: run DenyHosts in daemon mode")
    print(" --foreground: run DenyHosts in foreground mode")
    print(" --sync: run DenyHosts synchronization mode")
    print(" --version: Prints the version of DenyHosts and exits")

    print("\n")
    print("Note: multiple --file args can be processed. ")
    print("If multiple files are provided, --ignore is implied")
    print("\n")
    print("Note: multiple --purgeip arguments can be processed. ")
    print("\n")
    print("When run in --daemon mode the following flags are ignored:")
    print("     --file, --purge, --purge-all, --purgeip, --migrate, --sync, --verbose")


#################################################################################




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
    try:
        (opts, getopts) = getopt.getopt(args, 'f:c:dinuvps?hV',
                                        ["file=", "ignore", "verbose", "debug",
                                         "help", "noemail", "config=", "version",
                                         "migrate", "purge", "purge-all", "purgeip", "daemon", "foreground",
                                         "unlock", "sync", "upgrade099"])
    except GetoptError:
        print("\nInvalid command line option detected.")
        usage()
        sys.exit(1)

    for opt, arg in opts:
        if opt in ('-h', '-?', '--help'):
            usage()
            sys.exit(0)
        if opt in ('-f', '--file'):
            logfiles.append(arg)
        if opt in ('-i', '--ignore'):
            ignore_offset = 1
        if opt in ('-n', '--noemail'):
            noemail = 1
        if opt in ('-v', '--verbose'):
            verbose = 1
        if opt in ('-d', '--debug'):
            enable_debug = 1
        if opt in ('-c', '--config'):
            config_file = arg
        if opt in ('-m', '--migrate'):
            migrate = 1
        if opt in ('-p', '--purge'):
            purge = 1
        if opt in ('-s', '--sync'):
            sync_mode = 1
        if opt in ('-s', '--unlock'):
            unlock = 1
        if opt == '--daemon':
            daemon = 1
        if opt == '--foreground':
            foreground = 1
        if opt == '--purge-all':
            purge_all = 1
        if opt == '--purgeip':
            purgeip_list.append(arg)
            purgeip = 1
        if opt == '--upgrade099':
            upgrade099 = 1
        if opt == '--version':
            print("DenyHosts version:", VERSION)
            sys.exit(0)

    # This is generally expected to be in the environment, but there's no
    # non-hackish way to get systemd to set it, so just hack it in here.
    os.environ['HOSTNAME'] = platform.node()

    prefs = Prefs(config_file)

    first_time = 0
    try:
        if not os.path.exists( prefs.get('WORK_DIR') ):
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
        if (host_filename): 
            fp = open( prefs.get("HOSTS_DENY"), "a" )
            fp.close();
    except Exception as e:
        print("Unable to create file specified by HOSTS_DENY variable.")

    setup_logging(prefs, enable_debug, verbose, daemon)

    if not logfiles or daemon:
        logfiles = [prefs.get('SECURE_LOG')]
    elif len(logfiles) > 1:
        ignore_offset = 1

    if not prefs.get('ADMIN_EMAIL'): noemail = 1

    lock_file = LockFile(prefs.get('LOCK_FILE'))

    if unlock:
        if os.path.isfile( prefs.get('LOCK_FILE') ):
           lock_file.remove()

    lock_file.create()

    if upgrade099 and not (daemon or foreground):
        if not prefs.get('PURGE_DENY'):
            lock_file.remove()
            die("You have supplied the --upgrade099 flag, however you have not set PURGE_DENY in your configuration file")
        else:
            u = UpgradeTo099(prefs.get("HOSTS_DENY"))

    if migrate and not (daemon or foreground):
        if not prefs.get('PURGE_DENY'):
            lock_file.remove()
            die("You have supplied the --migrate flag however you have not set PURGE_DENY in your configuration file.")
        else:
            m = Migrate(prefs.get("HOSTS_DENY"))

    # clear out specific IP addresses
    if purgeip and not daemon:
        if len(purgeip_list) < 1:
            lock_file.remove()
            die("You have provided the --purgeip flag however you have not listed any IP addresses to purge.")
        else:
            try:
                p = PurgeIP(prefs,
                          purgeip_list)

            except Exception as e:
                lock_file.remove()
                die(str(e))


    # Try to purge old records without any delay
    if purge_all and not daemon:
         purge_time = 1
         try:
            p = Purge(prefs, purge_time)
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
                p = Purge(prefs,
                          purge_time)

            except Exception as e:
                lock_file.remove()
                die(str(e))

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
           die("You have provided the --sync flag however your configuration file has SYNC_UPLOAD and SYNC_DOWNLOAD set to false.")
        try:
            sync = Sync(prefs)
            if sync_upload:
                timestamp = sync.send_new_hosts()
            if sync_download:
                new_hosts = sync.receive_new_hosts()
                if new_hosts:
                    # MMR: What is 'info' here?
                    info("received new hosts: %s", str(new_hosts))
                    sync.get_denied_hosts()
                    sync.update_hosts_deny(new_hosts)
                    dh.get_denied_hosts()
                    dh.update_hosts_deny(new_hosts)
            sync.xmlrpc_disconnect()
        except Exception as e:
            lock_file.remove()
            die("Error synchronizing data", e)

    # remove lock file on exit
    lock_file.remove()
