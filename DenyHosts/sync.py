import logging
import os
import time
import sys

if sys.version_info < (3, 0): 
    from xmlrpclib import ServerProxy
else:
    from xmlrpc.client import ServerProxy

from .constants import SYNC_TIMESTAMP, SYNC_HOSTS, SYNC_HOSTS_TMP, SYNC_RECEIVED_HOSTS

logger = logging.getLogger("sync")
debug, info, error, exception = logger.debug, logger.info, logger.error, logger.exception


def get_plural(items):
    if len(items) != 1:
        return "s"
    else:
        return ""


class Sync(object):
    def __init__(self, prefs):
        self.__prefs = prefs
        self.__work_dir = prefs.get('WORK_DIR')
        self.__connected = False
        self.__hosts_added = []
        self.__server = None

    def xmlrpc_connect(self):
        try:
            self.__server = ServerProxy(self.__prefs.get('SYNC_SERVER'))
            self.__connected = True
        except Exception as e:
            error(str(e))
            self.__connected = False
        return self.__connected

    def xmlrpc_disconnect(self):
        if self.__connected:
            try:
                # self.__server.close()
                self.__server = None
            except Exception:
                pass
            self.__connected = False

    def get_sync_timestamp(self):
        timestamp = 0
        try:
            with open(os.path.join(self.__work_dir, SYNC_TIMESTAMP)) as fp:
                line = fp.readline().strip()
                if len(line) > 0:
                    timestamp = int(line)
                    return timestamp
            return timestamp
        except Exception as e:
            error(str(e))
            return 0

    def set_sync_timestamp(self, timestamp):
        try:
            with open(os.path.join(self.__work_dir, SYNC_TIMESTAMP), "w") as fp:
                fp.write(timestamp)
        except Exception as e:
            error(e)

    def send_new_hosts(self):
        debug("send_new_hosts()")
        self.__hosts_added = []
        try:
            src_file = os.path.join(self.__work_dir, SYNC_HOSTS)
            dest_file = os.path.join(self.__work_dir, SYNC_HOSTS_TMP)
            os.rename(src_file, dest_file)
        except OSError:
            return False

        hosts = []
        with open(dest_file, 'r') as fp:
            # less memory usage than using readlines()
            for line in fp:
                hosts.append(line.strip())

        try:
            self.__send_new_hosts(hosts)
            info("sent %d new host%s", len(hosts), get_plural(hosts))
            self.__hosts_added = hosts
        except Exception:
            os.rename(dest_file, src_file)
            return False

        try:
            os.unlink(dest_file)
        except OSError:
            pass

        return True

    def __send_new_hosts(self, hosts):
        if not self.__connected and not self.xmlrpc_connect():
            error("Could not initiate xmlrpc connection")
            return

        try:
            self.__server.add_hosts(hosts)
        except Exception as e:
            exception(e)

    def receive_new_hosts(self):
        debug("receive_new_hosts()")

        if not self.__connected and not self.xmlrpc_connect():
            error("Could not initiate xmlrpc connection")
            return
        timestamp = self.get_sync_timestamp()

        try:
            data = self.__server.get_new_hosts(
                timestamp,
                self.__prefs.get("SYNC_DOWNLOAD_THRESHOLD"),
                self.__hosts_added,
                self.__prefs.get("SYNC_DOWNLOAD_RESILIENCY")
            )
            timestamp = data['timestamp']
            self.set_sync_timestamp(timestamp)
            hosts = data['hosts']
            info("received %d new host%s", len(hosts), get_plural(hosts))
            self.__save_received_hosts(hosts, timestamp)
            return hosts
        except Exception as e:
            exception(e)
            return None

    def __save_received_hosts(self, hosts, timestamp):
        try:
            timestr = time.ctime(float(timestamp))
            with open(os.path.join(self.__work_dir, SYNC_RECEIVED_HOSTS), "a") as fp:
                for host in hosts:
                    fp.write("%s:%s\n" % (host, timestr))
        except IOError as e:
            error(e)
            return
        finally:
            fp.close()
