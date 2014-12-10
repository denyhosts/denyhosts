import logging
import os

error = logging.getLogger("plugin").error
info = logging.getLogger("plugin").info
debug = logging.getLogger("plugin").debug

def execute(executable, hosts):
    for host in hosts:
        debug("invoking plugin: %s %s", executable, host)
        try:
            res = os.system("%s %s" % (executable, host))
            if res: info("plugin returned %d", res)
        except Exception, e:
            error("plugin error: %s", e)
