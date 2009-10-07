import sys


def check_version():
    version_tuple = sys.version_info
    version = version_tuple[0] * 100 + version_tuple[1]
    if version < 203:
        print "Python >= 2.3 required.  You are using:", sys.version

        print """
######################################################################

Visit http://www.python.org and download a more recent version of
Python.

You should install this version in addition to your current version
(rather than upgrading your current version) because your system might
depend on the current version.  After installing the newer version, for
instance version 2.4, simply invoke DenyHosts explicitly with the new
version of python, eg:

$ python2.4 %s

######################################################################

""" % ' '.join(sys.argv)

        sys.exit(1)


check_version()
