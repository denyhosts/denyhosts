#!/usr/bin/env python
# Copyright 2005-2006 (C) Phil Schwartz <phil_schwartz@users.sourceforge.net>
# Copyright 2014 (C) Jesse Smith <jessefrgsmith@yahoo.ca>

from DenyHosts.version import VERSION
from distutils.core import setup
import os
import os.path
import sys
from glob import glob


etcpath = "/etc"
manpath = "/usr/share/man/man8"
libpath = "/usr/share/denyhosts"
scriptspath = "%s/scripts" % libpath
pluginspath = "%s/plugins" % libpath

#########################################################################

setup(name="DenyHost",
      version=VERSION,
      description="DenyHost is a utility to help sys admins thwart ssh hackers",
      author="Jesse Smith",
      author_email="jessefrgsmith@yahoo.ca",
      url="http://denyhost.sourceforge.net",
      scripts=['denyhosts.py', 'daemon-control-dist'],
      package_dir={'DenyHosts': 'DenyHosts'},
      packages=["DenyHosts"],
      data_files=[(etcpath, glob("denyhosts.conf")),
                  (manpath, glob("denyhosts.8"))],
#      data_files=[(libpath, glob("denyhosts.cfg-dist")),
#                  (libpath, glob("setup.py")),
#                  (libpath, glob("daemon-control-dist")),
#                  (libpath, glob("CHANGELOG.txt")),
#                  (libpath, glob("README.txt")),
#                  (scriptspath, glob("scripts/*")),
#                  (pluginspath, glob("plugins/*")),
#                  (libpath, glob("LICENSE.txt"))],
      license="GPL v2",
      ##extra_path='denyhosts',
      long_description="""
DenyHosts is a python program that automatically blocks ssh attacks by adding entries to 
/etc/hosts.deny. DenyHosts will also inform administrators about offending hosts, attacked 
users and suspicious logins. Originally written by Phil Schwartz."
      """
      )

