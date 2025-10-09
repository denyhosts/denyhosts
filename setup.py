#!/usr/bin/env python
# Copyright 2005-2006 (C) Phil Schwartz <phil_schwartz@users.sourceforge.net>
# Copyright 2014 (C) Jesse Smith <jessefrgsmith@yahoo.ca>

from glob import glob
import sys
from os.path import join as ospj
from os.path import exists as fcheck

from setuptools import setup

from DenyHosts.util import normalize_whitespace
from DenyHosts.version import VERSION

etcpath = "/etc"
manpath = "/usr/share/man/man8"
libpath = "/usr/share/denyhosts"
scriptspath = ospj("scripts", libpath)
pluginspath = ospj("plugins", libpath)
denyhostsman = 'denyhosts.8'

if 'rpm' in sys.argv[1]:
    denyhostsman += '.gz'

if fcheck(etcpath + '/' + 'denyhosts.conf'):
    backup = ['Y', 'y', 'yes', 'YES', 'Yes', '']
    backup_question = 'We have detected that you have an existing config file, would you like to back it up? [Y|N]: '
    try:  # python 2.x
        backup_file = raw_input(backup_question)
    except NameError:  # python 3
        backup_file = input(backup_question)

    if backup_file in backup:
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
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
    long_description=normalize_whitespace(
        """
        DenyHosts is a python program that automatically blocks ssh attacks
        by adding entries to /etc/hosts.deny. DenyHosts will also inform
        administrators about offending hosts, attacked users and suspicious
        logins. Originally written by Phil Schwartz.
        """
    ),
)
