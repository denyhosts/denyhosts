#!/usr/bin/env python
# Copyright 2005-2006 (C) Phil Schwartz <phil_schwartz@users.sourceforge.net>
# Copyright 2014 (C) Jesse Smith <jessefrgsmith@yahoo.ca>

from glob import glob
from os.path import join as ospj

from distutils.core import setup

from DenyHosts.util import normalize_whitespace
from DenyHosts.version import VERSION

etcpath = "/etc"
manpath = "/usr/share/man/man8"
libpath = "/usr/share/denyhosts"
scriptspath = ospj("scripts", libpath)
pluginspath = ospj("plugins", libpath)

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
    data_files=[
        (etcpath, glob("denyhosts.conf")),
        (manpath, glob("denyhosts.8")),
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
