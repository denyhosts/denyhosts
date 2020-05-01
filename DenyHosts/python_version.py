import sys
from textwrap import dedent

MINIMUM_VERSION = (2, 4)


def check_version():
    if sys.version_info < MINIMUM_VERSION:
        min_version_str = '.'.join(str(x) for x in MINIMUM_VERSION)
        print("Python >= %s required.  You are using:\n%s" % (min_version_str, sys.version))

        print(dedent("""
            ######################################################################

            Visit http://www.python.org and download a more recent version of
            Python.

            You should install this version in addition to your current version
            (rather than upgrading your current version) because your system might
            depend on the current version.  After installing the newer version, for
            instance version 3.2, simply invoke DenyHosts explicitly with the new
            version of python, eg:

            $ python3.4 %s

            ######################################################################

            """) % ' '.join(sys.argv))
        sys.exit(1)


check_version()
