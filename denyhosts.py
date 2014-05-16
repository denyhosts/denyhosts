#!/usr/bin/env python
import os
import sys

import DenyHosts.python_version

import getopt
import traceback
import logging

from DenyHosts.util import die, setup_logging, is_true
from DenyHosts.lockfile import LockFile
from DenyHosts.prefs import Prefs
from DenyHosts.version import VERSION
from DenyHosts.deny_hosts import DenyHosts
from DenyHosts.denyfileutil import Purge, Migrate, UpgradeTo099
from DenyHosts.constants import *
from DenyHosts.sync import Sync

#################################################################################



def usage():
    print "Usage:"
    print "%s [-f logfile | --file=logfile] [ -c configfile | --config=configfile] [-i | --ignore] [-n | --noemail] [--purge] [--migrate] [--daemon] [--sync] [--version]" % sys.argv[0]
    print
    print
    print " --file:   The name of log file to parse"
    print " --ignore: Ignore last processed offset (start processing from beginning)"
    print " --noemail: Do not send an email report"
    print " --unlock: if lockfile exists, remove it and run as normal"
    print " --migrate: migrate your HOSTS_DENY file so that it is suitable for --purge"
    print " --purge: expire entries older than your PURGE_DENY setting"
    print " --daemon: run DenyHosts in daemon mode"
    print " --sync: run DenyHosts synchronization mode"
    print " --version: Prints the version of DenyHosts and exits"
    
    print
    print "Note: multiple --file args can be processed. ",
    print "If multiple files are provided, --ignore is implied"
    print
    print "When run in --daemon mode the following flags are ignored:"
    print "     --file, --purge, --migrate, --sync, --verbose"


#################################################################################


                

#################################################################################

    
if __name__ == '__main__':
    logfiles = []
    config_file = CONFIG_FILE
    ignore_offset = 0
    noemail = 0
    verbose = 0
    migrate = 0
    purge = 0
    sync_mode = 0
    daemon = 0
    enable_debug = 0
    upgrade099 = 0
    args = sys.argv[1:]
    try:
        (opts, getopts) = getopt.getopt(args, 'f:c:dinuvps?hV',
                                        ["file=", "ignore", "verbose", "debug", 
                                         "help", "noemail", "config=", "version",
                                         "migrate", "purge", "daemon", "sync",
                                         "upgrade099"])
    except:
        print "\nInvalid command line option detected."
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
        if opt == '--daemon':
            daemon = 1
        if opt == '--upgrade099':
            upgrade099 = 1
        if opt == '--version':
            print "DenyHosts version:", VERSION
            sys.exit(0)

    prefs = Prefs(config_file)    
            
    first_time = 0
    try:
        os.makedirs(prefs.get('WORK_DIR'))
        first_time = 1
    except Exception, e:
        if e[0] != 17:
            print e
            sys.exit(1)

    setup_logging(prefs, enable_debug, verbose, daemon)
    
    if not logfiles or daemon:
        logfiles = [prefs.get('SECURE_LOG')]
    elif len(logfiles) > 1:
        ignore_offset = 1

    if not prefs.get('ADMIN_EMAIL'): noemail = 1

    lock_file = LockFile(prefs.get('LOCK_FILE'))

    lock_file.create()

    if upgrade099 and not daemon:
        if not prefs.get('PURGE_DENY'):
            lock_file.remove()
            die("You have supplied the --upgrade099 flag, however you have not set PURGE_DENY in your configuration file")
        else:
            u = UpgradeTo099(prefs.get("HOSTS_DENY"))

    if migrate and not daemon:
        if not prefs.get('PURGE_DENY'):
            lock_file.remove()
            die("You have supplied the --migrate flag however you have not set PURGE_DENY in your configuration file.")
        else:
            m = Migrate(prefs.get("HOSTS_DENY"))

    if purge and not daemon:
        purge_time = prefs.get('PURGE_DENY')
        if not purge_time:
            lock_file.remove()
            die("You have provided the --purge flag however you have not set PURGE_DENY in your configuration file.")
        else:
            try:
                p = Purge(prefs, 
                          purge_time)

            except Exception, e:
                lock_file.remove()
                die(str(e))

    try:
        for f in logfiles:
            dh = DenyHosts(f, prefs, lock_file, ignore_offset,
                           first_time, noemail, daemon)
    except SystemExit, e:
        pass
    except Exception, e:
        traceback.print_exc(file=sys.stdout)
        print "\nDenyHosts exited abnormally"


    if sync_mode and not daemon:
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
                    info("received new hosts: %s", str(new_hosts))
                    sync.get_denied_hosts()
                    sync.update_hosts_deny(new_hosts)
            sync.xmlrpc_disconnect()
        except Exception, e:
            lock_file.remove()
            die("Error synchronizing data", e)
        
    # remove lock file on exit
    lock_file.remove()
            
