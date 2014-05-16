"""Disk And Execution MONitor (Daemon)

Default daemon behaviors (they can be modified):
   1.) Ignore SIGHUP signals.
   2.) Default current working directory to the "/" directory.
   3.) Set the current file creation mode mask to 0.
   4.) Close all open files (0 to [SC_OPEN_MAX or 256]).
   5.) Redirect standard I/O streams to "/dev/null".

Failed fork() calls will return a tuple: (errno, strerror).  This behavior
can be modified to meet your program's needs.

Resources:
   Advanced Programming in the Unix Environment: W. Richard Stevens
   Unix Network Programming (Volume 1): W. Richard Stevens
   http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
"""

__author__ = "Chad J. Schroeder"
__version__ = "$Id$"

import os               # Miscellaneous OS interfaces.
import sys              # System-specific parameters and functions.
import signal           # Set handlers for asynchronous events.
import time

def createDaemon():
   """Detach a process from the controlling terminal and run it in the
   background as a daemon.
   """

   try:
      # Fork a child process so the parent can exit.  This will return control
      # to the command line or shell.  This is required so that the new process
      # is guaranteed not to be a process group leader.  We have this guarantee
      # because the process GID of the parent is inherited by the child, but
      # the child gets a new PID, making it impossible for its PID to equal its
      # PGID.
      pid = os.fork()
   except OSError, e:
      return((e.errno, e.strerror))     # ERROR (return a tuple)

   if (pid == 0):       # The first child.

      # Next we call os.setsid() to become the session leader of this new
      # session.  The process also becomes the process group leader of the
      # new process group.  Since a controlling terminal is associated with a
      # session, and this new session has not yet acquired a controlling
      # terminal our process now has no controlling terminal.  This shouldn't
      # fail, since we're guaranteed that the child is not a process group
      # leader.
      os.setsid()

      # When the first child terminates, all processes in the second child
      # are sent a SIGHUP, so it's ignored.
      signal.signal(signal.SIGHUP, signal.SIG_IGN)

      try:
         # Fork a second child to prevent zombies.  Since the first child is
         # a session leader without a controlling terminal, it's possible for
         # it to acquire one by opening a terminal in the future.  This second
         # fork guarantees that the child is no longer a session leader, thus
         # preventing the daemon from ever acquiring a controlling terminal.
         pid = os.fork()        # Fork a second child.
      except OSError, e:
         return((e.errno, e.strerror))  # ERROR (return a tuple)

      if (pid == 0):      # The second child.
         # Ensure that the daemon doesn't keep any directory in use.  Failure
         # to do this could make a filesystem unmountable.
         os.chdir("/")
         # Give the child complete control over permissions.
         os.umask(0)
      else:
         os._exit(0)      # Exit parent (the first child) of the second child.
   else:
      os._exit(0)         # Exit parent of the first child.

   std_fds = 3   # 0,1,2
   for fd in range(0, std_fds):
      try:
         os.close(fd)
      except OSError:   # ERROR (ignore)
         pass

   # Redirect the standard file descriptors to /dev/null.
   os.open("/dev/null", os.O_RDONLY)     # standard input (0)
   os.open("/dev/null", os.O_RDWR)       # standard output (1)
   os.open("/dev/null", os.O_RDWR)       # standard error (2)

   return(0)

if __name__ == "__main__":

   # Self-test.

   retCode = createDaemon()

   # If executed with superuser privilages, there should be a new file in the
   # "/" directory.  It should contain the function's return code, the daemon's
   # PID, PPID, and PGRP.  Its PID should not equal its PGRP, and its PPID
   # should equal 1.  If it's executed without superuser privilages, the file
   # won't be created and no errors will be reported.
   open("createDaemon.log", "w").write("rc: %s; pid: %d; ppid: %d; pgrp: %d" %\
      (retCode, os.getpid(), os.getppid(), os.getpgrp()))

   sys.exit(0)
