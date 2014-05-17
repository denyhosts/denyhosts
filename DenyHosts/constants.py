
import sys

#################################################################################
#        These files will be created relative to prefs WORK_DIR                 #
#################################################################################

SECURE_LOG_OFFSET = "offset"
DENIED_TIMESTAMPS = "denied-timestamps"

ABUSIVE_HOSTS_INVALID = "hosts"
ABUSIVE_HOSTS_VALID = "hosts-valid"
ABUSIVE_HOSTS_ROOT = "hosts-root"
ABUSIVE_HOSTS_RESTRICTED = "hosts-restricted"

ABUSED_USERS_INVALID = "users-invalid"
ABUSED_USERS_VALID = "users-valid"
ABUSED_USERS_AND_HOSTS = "users-hosts"                              
SUSPICIOUS_LOGINS = "suspicious-logins"   # successful logins AFTER invalid
                                          #   attempts from same host

ALLOWED_HOSTS = "allowed-hosts"
ALLOWED_WARNED_HOSTS = "allowed-warned-hosts"

RESTRICTED_USERNAMES = "restricted-usernames"

SYNC_TIMESTAMP = "sync-timestamp"
SYNC_HOSTS = "sync-hosts"
SYNC_HOSTS_TMP = "sync-hosts.tmp"
SYNC_RECEIVED_HOSTS = "sync-received"

PURGE_HISTORY = "purge-history"

#################################################################################
#                           Miscellaneous constants                             #
#################################################################################

CONFIG_FILE = "/etc/denyhosts.conf"

DENY_DELIMITER = "# DenyHosts:"
ENTRY_DELIMITER = " | "

TIME_SPEC_LOOKUP =  {'s': 1,        # s
                     'm': 60,       # minute
                     'h': 3600,     # hour
                     'd': 86400,    # day
                     'w': 604800,   # week
                     'y': 31536000} # year

SYNC_MIN_INTERVAL = 300 # 5 minutes

plat = sys.platform
if plat.startswith("freebsd"):
    # this has no effect if BLOCK_SERVICE is empty
    BSD_STYLE = " : deny"
else:
    BSD_STYLE = ""

