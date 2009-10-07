import re

#################################################################################
# REGULAR EXPRESSIONS ARE COOL.  Check out Kodos (http://kodos.sourceforge.net) #
#################################################################################

#DATE_FORMAT_REGEX = re.compile(r"""(?P<month>[A-z]{3,3})\s*(?P<day>\d+)""")

SSHD_FORMAT_REGEX = re.compile(r""".* (sshd.*:|\[sshd\]) (?P<message>.*)""")
#SSHD_FORMAT_REGEX = re.compile(r""".* sshd.*: (?P<message>.*)""")

FAILED_ENTRY_REGEX = re.compile(r"""Failed (?P<method>.*) for (?P<invalid>invalid user |illegal user )?(?P<user>.*?) from (::ffff:)?(?P<host>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""")

FAILED_ENTRY_REGEX2 = re.compile(r"""(Illegal|Invalid) user (?P<user>.*?) from (::ffff:)?(?P<host>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""")

FAILED_ENTRY_REGEX3 = re.compile(r"""Authentication failure for (?P<user>.*) from (::ffff:)?(?P<host>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""")

FAILED_ENTRY_REGEX4 = re.compile(r"""Authentication failure for (?P<user>.*) from (?P<host>.*)""")

SUCCESSFUL_ENTRY_REGEX = re.compile(r"""Accepted (?P<method>.*) for (?P<user>.*?) from (::ffff:)?(?P<host>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""")

TIME_SPEC_REGEX = re.compile(r"""(?P<units>\d*)\s*(?P<period>[smhdwy])?""")

ALLOWED_REGEX = re.compile(r"""(?P<first_3bits>\d{1,3}\.\d{1,3}\.\d{1,3}\.)((?P<fourth>\d{1,3})|(?P<ip_wildcard>\*)|\[(?P<ip_range>\d{1,3}\-\d{1,3})\])""")

PREFS_REGEX = re.compile(r"""(?P<name>.*?)\s*[:=]\s*(?P<value>.*)""")
