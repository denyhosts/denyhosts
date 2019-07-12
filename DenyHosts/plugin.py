import logging
import os

error = logging.getLogger("plugin").error
info = logging.getLogger("plugin").info
debug = logging.getLogger("plugin").debug


def execute(executable, hosts):
    for host in hosts:
        debug('invoking plugin: {0} {1}'.format(executable, host))
        try:
            res = os.system('{0} {1}'.format(executable, host))
            if res:
                info('plugin returned {0}'.format(res))
        except Exception as e:
            error('plugin error: {0}'.format(e))
