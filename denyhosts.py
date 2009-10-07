#!/usr/bin/env python
import os
import sys
import getopt
import traceback
import logging

from DenyHosts.util import die
from DenyHosts.lockfile import LockFile
from DenyHosts.prefs import Prefs
from DenyHosts.version import VERSION
from DenyHosts.constants import *
from DenyHosts.deny_hosts import DenyHosts
from DenyHosts.denyfileutil import Purge, Migrate

try:
    # python 2.4
    #logging.basicConfig(format="%(asctime)s - %(levelname)s - %(name)s - %(message)s")
    logging.basicConfig(format="%(message)s")
except:
    # python 2.3
    logging.basicConfig()
    hndlr = logging.getLogger().handlers[0]
    hndlr.setFormatter(logging.Formatter("%(message)s"))
    
debug = logging.getLogger("denyhosts").debug
info = logging.getLogger("denyhosts").info



#################################################################################



def usage():
    print "Usage:  %s [-f logfile | --file=logfile] [ -c configfile | --config=configfile] [-i | --ignore] [-n | --noemail] [-u | --unlock] [--purge] [--migrate] [--version]" % sys.argv[0]
    print
    print " --file:   The name of log file to parse"
    print " --ignore: Ignore last processed offset (start processing from beginning)"
    print " --noemail: Do not send an email report"
    print " --unlock: if lockfile exists, remove it and run as normal"
    print " --migrate: migrate your HOSTS_DENY file so that it is suitable for --purge"
    print " --purge: expire entries older than your PURGE_DENY setting"
    print " --version: Prints the version of DenyHosts and exits"
    print
    print "Note: multiple --file args can be processed. ",
    print "If multiple files are provided, --ignore is implied"
    print

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
    enable_debug = 0
    args = sys.argv[1:]
    try:
        (opts, getopts) = getopt.getopt(args, 'f:c:dinuvp?hV',
                                        ["file=", "ignore", "verbose", "debug", 
                                         "help", "noemail", "config=", "version",
                                         "migrate", "purge"])
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
            first_time = 0
        if opt in ('-d', '--debug'):
            enable_debug = 1
        if opt in ('-c', '--config'):
            config_file = arg
        if opt in ('-m', '--migrate'):
            migrate = 1
        if opt in ('-p', '--purge'):
            purge = 1                        
        if opt == '--version':
            print "DenyHosts version:", VERSION
            sys.exit(0)


    if verbose:
        logging.getLogger().setLevel(logging.INFO)
    elif enable_debug:
        logging.getLogger().setLevel(logging.DEBUG)


    prefs = Prefs(config_file)
    first_time = 0
    try:
        os.makedirs(prefs.get('WORK_DIR'))
        first_time = 1
    except Exception, e:
        if e[0] != 17:
            print e
            sys.exit(1)

    if enable_debug:
        print "Debug mode enabled."
        prefs.dump()
    
    if not logfiles:
        logfiles = [prefs.get('SECURE_LOG')]
    elif len(logfiles) > 1:
        ignore_offset = 1

    if not prefs.get('ADMIN_EMAIL'): noemail = 1

    lock_file = LockFile(prefs.get('LOCK_FILE'))

    lock_file.create()

    if migrate:
        if not prefs.get('PURGE_DENY'):
            lock_file.remove()
            die("You have supplied the --migrate flag however you have not set PURGE_DENY in your configuration file.")
        else:
            m = Migrate(prefs.get("HOSTS_DENY"))

    if purge:
        purge_time = prefs.get('PURGE_DENY')
        if not purge_time:
            lock_file.remove()
            die("You have provided the --purge flag however you have not set PURGE_DENY in your configuration file.")
        else:
            try:
                p = Purge(prefs.get('HOSTS_DENY'),
                          purge_time)
            except Exception, e:
                lock_file.remove()
                die(str(e))
        

    try:
        for f in logfiles:
            dh = DenyHosts(f, prefs, lock_file, ignore_offset,
                           first_time, noemail)
    except Exception, e:
        traceback.print_exc(file=sys.stdout)
        
    lock_file.remove()
            
