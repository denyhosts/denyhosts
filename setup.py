#!/usr/bin/env python
from version import VERSION
from distutils.core import setup
import os
import os.path
import sys
from glob import glob


libpath = "/usr/share/kodos"



#########################################################################

setup(name="DenyHosts",
      version=VERSION,
      description="DenyHosts is a utility to help sys admins thwart hackers",
      author="Phil Schwartz",
      author_email="phil_schwartz@users.sourceforge.net",
      url="http://denyhosts.sourceforge.net",
      scripts=['denyhosts.py'],
      ##package_dir={'': 'modules'},
      ##packages=['modules', "."],
      license="GPL",
      extra_path='kodos',
      long_description="""
DenyHosts is a python program that automatically blocks ssh attacks by adding entries to 
/etc/hosts.deny. DenyHosts will also inform Linux administrators about offending hosts, attacked 
users and suspicious logins.
      """
      )

