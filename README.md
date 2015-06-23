DenyHosts
=========

[![Build Status](https://travis-ci.org/denyhosts/denyhosts.svg)](https://travis-ci.org/denyhosts/denyhosts)

DenyHosts is a utility developed by Phil Schwartz and maintained by a
number of developers which aims to thwart sshd (ssh server) brute force attacks.

Please refer to https://github.com/denyhosts/denyhosts for more information.

Installation
============

Source Distribution
-------------------

If you downloaded the source distribution file (DenyHosts-#.#-tar.gz)
then:

    $ tar zxvf DenyHosts-3.0.tar.gz 

    $ cd denyhosts

as root:

    # python setup.py install

This will install the DenyHosts modules into python's site-packages
directory.

Binary Distribution (rpm, deb, etc)
-----------------------------------

It is assumed that you are familiar with installing a binary package
on your particular operating system. If you are unsure how to do
this, you may wish to install from source instead.


All Distributions
-----------------

DenyHosts requires that a configuration file be created before
it can function.  The sample configuration file denyhosts.conf
contains most of the possible settings and should be copied and
then edited as such:

    # cp denyhosts.conf /etc

    # nano /etc/denyhosts.conf

(nano is a simple text editor. Feel free to use your own favourite
text editor such as emacs, vi, etc)

The sample configuration file contains informational comments that
should help you quickly configure DenyHosts.  After you have
edited your configuration file, save it.

Next, if you intend to run DenyHosts in daemon mode (recommended)
copy the sample daemon-control.dist script as such:

    # cp daemon-control-dist daemon-control

Edit the daemon-control file.  You should only need to edit this section
near the top:

    ###############################################
    #### Edit these to suit your configuration ####
    ###############################################

    DENYHOSTS_BIN   = "/usr/bin/denyhosts.py"
    DENYHOSTS_LOCK  = "/var/lock/subsys/denyhosts"
    DENYHOSTS_CFG   = "/etc/denyhosts.conf"


These defaults should be reasonable for many systems.  You
should customize these settings to match your particular
system.

Once you have edited the configuration and daemon control files
make sure that the daemon control script it executable (by root).

    # chown root daemon-control

    # chmod 700 daemon-control


Starting DenyHosts Manually
===========================

Assuming you have configured DenyHosts to run as a daemon, you
can use the daemon-control script to control it:

    # daemon-control start

You should refer to the daemon log (typically /var/log/denyhosts)
to ensure that DenyHosts is running successfully.  If you
notice any problems you may wish to consult the FAQ at
http://www.denyhosts.net/faq.html

If you wish to run DenyHosts from cron rather than as a
daemon, please refer to the FAQ.

Another way to start DenyHosts manually is to run it from the command
line, usually supply a few common parameters. Usually, when running
DenyHosts from the command line (or from the /etc/rc.local script) we
can launch the program by running

     # python /usr/local/bin/denyhosts --config /etc/denyhosts.conf --daemon

The above command launches DenyHosts and runs it in the background. DenyHosts
will use the /etc/denyhosts.conf configuration file to dictate its behavour.


Starting DenyHosts Automatically
================================

Method 1 (preferred)
--------------------

Create a symbolic link from /etc/init.d such as:

    # cd /etc/init.d
    # ln -s /usr/share/denyhosts/daemon-control denyhosts

If you have chkconfig installed you can then use it to
ensure that DenyHosts runs at boot time:

    # chkconfig --add denyhosts

If you do not have chkconfig (or similar) installed you can either manually
create the symlinks in /etc/rc2.d, /etc/rc3.d, /etc/rc5.d but that is beyond
the scope of this document.

Method 2
--------

Add an entry into the /etc/rc.local file:

    /usr/share/denyhosts/daemon-control start

