import logging
import os
import time
import sys
import socket
import requests

if sys.version_info < (3, 0): 
    from xmlrpclib import ServerProxy, Fault
else:
    from xmlrpc.client import ServerProxy, Transport, ProtocolError, Fault

from .constants import SYNC_TIMESTAMP, SYNC_HOSTS, SYNC_HOSTS_TMP, SYNC_RECEIVED_HOSTS, SOCKET_TIMEOUT

logging.basicConfig()
logger = logging.getLogger('sync')
debug, info, error, exception = logger.debug, logger.info, logger.error, logger.exception


def get_plural(items):
    if len(items) != 1:
        return "s"
    else:
        return ""


if sys.version_info >= (3, 0):
    class RequestsTransport(Transport):

        def request(self, host, handler, data, verbose=False):
            # set the headers, including the user-agent
            headers = {"User-Agent": "my-user-agent",
                       "Content-Type": "text/xml",
                       "Accept-Encoding": "gzip"}
            url = "http://%s%s" % (host, handler)
            response = None
            try:
                response = requests.post(url, data=data, headers=headers, timeout=SOCKET_TIMEOUT)
                response.raise_for_status()
            except requests.RequestException as e:
                if response is None:
                    exception(ProtocolError(url, 500, str(e), ""))
                else:
                    exception(ProtocolError(
                        url,
                        response.status_code,
                        str(e),
                        response.headers
                    ))
            if response is not None:
                return self.parse_response(response)
            return response

        def parse_response(self, resp):
            """
            Parse the xmlrpc response.
            """
            p, u = self.getparser()
            p.feed(resp.text)
            p.close()
            return u.close()


class Sync(object):
    def __init__(self, prefs):
        self.__prefs = prefs
        self.__work_dir = prefs.get('WORK_DIR')
        self.__connected = False
        self.__hosts_added = []
        self.__server = None
        self.__default_timeout = socket.getdefaulttimeout()
        self.__pymajor_version = sys.version_info[0]
        self.__sync_server = self.__prefs.get('SYNC_SERVER')

    def xmlrpc_connect(self):
        debug("xmlrpc_conect()")
        # python 2
        if self.__pymajor_version == 2:
            socket.setdefaulttimeout(SOCKET_TIMEOUT)  # set global socket timeout
        for i in range(0, 3):
            debug("XMLRPC Connection attempt: %d" % i)
            try:
                # python 2
                if self.__pymajor_version == 2:
                    self.__server = ServerProxy(self.__sync_server)
                else:
                    self.__server = ServerProxy(self.__sync_server, transport=RequestsTransport())
                debug("Connected To SYNC Server")
                self.__connected = True
                break
            except Exception as e:
                error(str(e))
                self.__connected = False
            time.sleep(30)
        if not self.__connected:
            error('Failed to connect to %s after 3 attempts' % self.__sync_server)
        # python 2
        if self.__pymajor_version == 2:
            socket.setdefaulttimeout(self.__default_timeout)  # set timeout back to the default
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

    def send_release_used(self, dh_version):
        debug('Sending release version to sync server for tracking')
        try:
            py_version = '.'.join([str(x) for x in sys.version_info[0:3]])
            version_info = [py_version, dh_version]
            if not self.__connected and not self.xmlrpc_connect():
                error("Could not initiate xmlrpc connection")
                return

            for i in range(0, 3):
                try:
                    self.__server.version_report(version_info)
                    break
                except Fault as f:
                    if 8001 == f.faultCode:
                        debug('version_report procedure doesn\'t exist on the sync server: %s' % f.faultString)
                        break
                except Exception as e:
                    exception(e)
                time.sleep(30)
        except Exception as e:
            exception('Failure reporting your setup: %s' % e)
            pass
        finally:
            self.xmlrpc_disconnect()

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
        debug("__send_new_hosts()")
        if not self.__connected and not self.xmlrpc_connect():
            error("Could not initiate xmlrpc connection")
            return

        for i in range(0, 3):
            try:
                self.__server.add_hosts(hosts)
                break
            except Exception as e:
                exception(e)
            time.sleep(30)

    def receive_new_hosts(self):
        debug("receive_new_hosts()")

        data = self.__receive_new_hosts()
        if data is None:
            return None

        try:
            timestamp = data['timestamp']
            self.set_sync_timestamp(timestamp)
            hosts = data['hosts']
            info("received %d new host%s", len(hosts), get_plural(hosts))
            debug("hosts added %s", hosts)
            self.__save_received_hosts(hosts, timestamp)
            return hosts
        except Exception as e:
            exception(e)
            return None

    def __receive_new_hosts(self):
        debug("__receive_new_hosts()")

        if not self.__connected and not self.xmlrpc_connect():
            error("Could not initiate xmlrpc connection")
            return
        timestamp = self.get_sync_timestamp()

        sync_dl_threshold = self.__prefs.get("SYNC_DOWNLOAD_THRESHOLD")
        sync_dl_resiliency = self.__prefs.get("SYNC_DOWNLOAD_RESILIENCY")
        data = None
        for i in range(0, 3):
            try:
                data = self.__server.get_new_hosts(
                    timestamp,
                    sync_dl_threshold,
                    self.__hosts_added,
                    sync_dl_resiliency
                )
                break
            except Exception as e:
                exception(e)
                pass
            time.sleep(30)

        if data is None:
            error('Unable to retrieve data from the sync server')
        return data

    def __save_received_hosts(self, hosts, timestamp):
        debug('__save_received_hosts()')
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

