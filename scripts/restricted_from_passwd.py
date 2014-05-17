#!/usr/bin/env python
#
############################################################################
# this script will read the /etc/passwd file and extract usernames
# that have one of the RESTRICTED_SHELLS.  The ouput of this
# script is a list of these restricted usernames suitable for
# use in WORK_DIR/restricted-usernames
#
# such as: python restricted_from_passwd > $WORK_DIR/restricted-usernames
# where $WORK_DIR is your DenyHosts WORK_DIR parameter
#
############################################################################

RESTRICTED_SHELLS = ("/sbin/nologin",
                     "/usr/sbin/nologin",
                     "/sbin/shutdown",
                     "/sbin/halt")

from pwd import getpwall

passwd = getpwall()

usernames = []
for pw_tuple in passwd:
    if pw_tuple[6] in RESTRICTED_SHELLS:
        usernames.append(pw_tuple[0])

usernames.sort()
for username in usernames:
    print username
    
                     
