#!/usr/bin/env python
# Copyright 2005-2006 (C) Phil Schwartz <phil_schwartz@users.sourceforge.net>
# Copyright 2014 (C) Jesse Smith <jessefrgsmith@yahoo.ca>

from glob import glob
import sys
from os.path import join as ospj
from os.path import exists as fcheck

from distutils.core import setup
from DenyHosts.my_ip import MyIp
from DenyHosts.prefs import Prefs
from DenyHosts.util import normalize_whitespace
from DenyHosts.version import VERSION
from DenyHosts.constants import ALLOWED_HOSTS
from DenyHosts.allowedhosts import AllowedHosts

etcpath = "/etc"
manpath = "/usr/share/man/man8"
libpath = "/usr/share/denyhosts"
scriptspath = ospj("scripts", libpath)
pluginspath = ospj("plugins", libpath)
denyhostsman = 'denyhosts.8'

if 'rpm' in sys.argv[1]:
    denyhostsman += '.gz'

yes = ['Y', 'y', 'yes', 'YES', 'Yes', '']
if fcheck(etcpath + '/' + 'denyhosts.conf'):
    backup_question = 'We have detected that you have an existing config file, would you like to back it up? [Y|N]: '
    try:  # python 2.x
        backup_file = raw_input(backup_question)
    except NameError:  # python 3
        backup_file = input(backup_question)

    if backup_file in yes:
        from distutils.file_util import copy_file
        from time import time

        copy_file(
            (etcpath + '/' + 'denyhosts.conf'),
            (etcpath + '/' + 'denyhosts.conf.{0}'.format(int(time())))
        )

setup(
    name="DenyHosts",
    version=VERSION,
    description="DenyHost is a utility to help sys admins thwart ssh hackers",
    author="Jesse Smith",
    author_email="jessefrgsmith@yahoo.ca",
    url="http://denyhost.sourceforge.net",
    scripts=['denyhosts.py', 'daemon-control-dist'],
    package_dir={'DenyHosts': 'DenyHosts'},
    packages=["DenyHosts"],
    requires=["ipaddr"],
    data_files=[
        (etcpath, glob("denyhosts.conf")),
        (manpath, glob(denyhostsman)),
    ],
    license="GPL v2",
    long_description=normalize_whitespace(
        """
        DenyHosts is a python program that automatically blocks ssh attacks
        by adding entries to /etc/hosts.deny. DenyHosts will also inform
        administrators about offending hosts, attacked users and suspicious
        logins. Originally written by Phil Schwartz.
        """
    ),
)

"""
    This section adds detected public ips to the allowed_hosts file
    Also, gives the user the option to add in their own ip addresses to whitelist
"""
prefs = Prefs(ospj(etcpath, 'denyhosts.conf'))
work_dir = prefs.get('WORK_DIR')
allowed_hosts = AllowedHosts(prefs)
allowed_ips = list(allowed_hosts.allowed_hosts.keys())

detect_ips_quest = 'Would you like us to attempt to detect your public ip? [Y|N] (default Y) '
try:  # python 2.x
    detect_ips = raw_input(detect_ips_quest)
except NameError:  # python 3
    detect_ips = input(detect_ips_quest)

if detect_ips in yes:
    myip = MyIp(prefs=prefs)
    public_ips = myip.get_remote_ip()
    for public_ip in public_ips:
        allowed_ips.append(public_ip)

extra_ips_quest = 'Add additional ip addresses here to whitelist (ex: 172.202.43.1,172.203,44.2): '
try:  # python 2.x
    extra_ips = raw_input(extra_ips_quest)
except NameError:  # python 3
    extra_ips = input(extra_ips_quest)

if extra_ips.strip() != "":
    extra_ips_list = extra_ips.split(',')
    for i in range(0, len(extra_ips_list)):
        allowed_ips.append(extra_ips_list[i].strip())

print('Adding %s to %s' % (allowed_ips, ospj(work_dir, ALLOWED_HOSTS)))
if len(allowed_ips) > 0:
    with open(ospj(work_dir, ALLOWED_HOSTS), 'w') as fh:
        fh.writelines('{}\n'.format(allowed_ip) for allowed_ip in allowed_ips)

