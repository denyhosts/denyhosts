#!/usr/bin/env python
# Copyright 2005-2006 (C) Phil Schwartz <phil_schwartz@users.sourceforge.net>
from DenyHosts.version import VERSION
from distutils.core import setup
from glob import glob

libpath = "/usr/share/denyhosts"
scriptspath = "%s/scripts" % libpath
pluginspath = "%s/plugins" % libpath

#########################################################################

# Run 2to3 builder if we're on Python 3.x, from
#   http://wiki.python.org/moin/PortingPythonToPy3k
try:
    from distutils.command.build_py import build_py_2to3 as build_py
except ImportError:
    # 2.x
    from distutils.command.build_py import build_py
command_classes = {'build_py': build_py}

setup(name="DenyHosts",
      version=VERSION,
      description="DenyHosts is a utility to help sys admins thwart ssh hackers",
      author="Phil Schwartz",
      author_email="phil_schwartz@users.sourceforge.net",
      url="http://denyhosts.sourceforge.net",
      scripts=['denyhosts.py'],
      package_dir={'DenyHosts': 'DenyHosts'},
      packages=["DenyHosts"],
      data_files=[(libpath, glob("denyhosts.cfg-dist")),
                  (libpath, glob("setup.py")),
                  (libpath, glob("daemon-control-dist")),
                  (libpath, glob("CHANGELOG.txt")),
                  (libpath, glob("README.txt")),
                  (scriptspath, glob("scripts/*")),
                  (pluginspath, glob("plugins/*")),
                  (libpath, glob("LICENSE.txt"))],
      license="GPL v2",
      ##extra_path='denyhosts',
      long_description="""
DenyHosts is a python program that automatically blocks ssh attacks by adding entries to
/etc/hosts.deny. DenyHosts will also inform Linux administrators about offending hosts, attacked
users and suspicious logins.
      """,
      cmdclass=command_classes
      )

