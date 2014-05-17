from xmlrpclib import ServerProxy, Transport
from httplib import HTTP
import logging
import os
import time
from constants import SYNC_TIMESTAMP, SYNC_HOSTS, SYNC_HOSTS_TMP, SYNC_RECEIVED_HOSTS
debug = logging.getLogger("sync").debug
info = logging.getLogger("sync").info
error = logging.getLogger("sync").error
exception = logging.getLogger("sync").exception

def get_plural(items):
    if len(items) != 1:  return "s"
    else:                return ""

class ProxiedTransport(Transport):
    def set_proxy(self, proxy):
        self.proxy = proxy

    def make_connection(self, host):
        self.realhost = host
        h = HTTP(self.proxy)
        return h

    def send_request(self, connection, handler, request_body):
        connection.putrequest("POST", 'http://%s%s' % (self.realhost, handler))

    def send_host(self, connection, host):
        connection.putheader('Host', self.realhost)

class Sync:
    def __init__(self, prefs):
        self.__prefs = prefs
        self.__work_dir = prefs.get('WORK_DIR')
        self.__connected = False
        self.__hosts_added = []

    def xmlrpc_connect(self):
        try:
            p = ProxiedTransport()
            p.set_proxy(self.__prefs.get('SYNC_PROXY_SERVER'))
            self.__server = ServerProxy(self.__prefs.get('SYNC_SERVER'), transport=p)
            self.__connected = True
        except Exception, e:
            error(str(e))
            self.__connected = False
        return self.__connected


    def xmlrpc_disconnect(self):
        if self.__connected:
            try:
                #self.__server.close()
                self.__server = None
            except:
                pass
            self.__connected = False


    def get_sync_timestamp(self):
        try:
            fp = open(os.path.join(self.__work_dir, 
                                   SYNC_TIMESTAMP))
            timestamp = fp.readline()
            timestamp = long(timestamp.strip())
            return timestamp
        except Exception, e:
            error(str(e))
            return 0l

    def set_sync_timestamp(self, timestamp):
        try:
            fp = open(os.path.join(self.__work_dir,
                                   SYNC_TIMESTAMP), "w")
            fp.write(timestamp)
        except e:
            error(e)


    def send_new_hosts(self):
        debug("send_new_hosts()")
        self.__hosts_added = []
        try:
            src_file = os.path.join(self.__work_dir, SYNC_HOSTS)
            dest_file = os.path.join(self.__work_dir, SYNC_HOSTS_TMP)
            os.rename(src_file, dest_file)
        except:
            return False

        hosts = []
        fp = open(dest_file, "r")
        for line in fp.readlines():
            hosts.append(line.strip())
        fp.close()

        try:
            self.__send_new_hosts(hosts)
            info("sent %d new host%s", len(hosts), get_plural(hosts))
            self.__hosts_added = hosts
        except:
            os.rename(dest_file, src_file)
            return False
        
        try:
            os.unlink(dest_file)
        except:
            pass
        
        return True


    def __send_new_hosts(self, hosts):
        if not self.__connected and not self.xmlrpc_connect():
            error("Could not initiate xmlrpc connection")
            return

        try:
            self.__server.add_hosts(hosts)
        except Exception, e:
            exception(e)


    def receive_new_hosts(self):
        debug("receive_new_hosts()")
        
        if not self.__connected and not self.xmlrpc_connect():
            error("Could not initiate xmlrpc connection")
            return
        timestamp = self.get_sync_timestamp()

        try:
            data = self.__server.get_new_hosts(timestamp, 
                                               self.__prefs.get("SYNC_DOWNLOAD_THRESHOLD"),
                                               self.__hosts_added,
                                               self.__prefs.get("SYNC_DOWNLOAD_RESILIENCY"))
            timestamp = data['timestamp']
            self.set_sync_timestamp(timestamp)
            hosts = data['hosts']
            info("received %d new host%s", len(hosts), get_plural(hosts))
            self.__save_received_hosts(hosts, timestamp)
            return hosts 
        except Exception, e:
            exception(e)
            return None
        
    def __save_received_hosts(self, hosts, timestamp):
        try:
            fp = open(os.path.join(self.__work_dir, SYNC_RECEIVED_HOSTS), "a")
        except:
            error(e)
            return

        timestr = time.ctime(float(timestamp))
        for host in hosts:
            fp.write("%s:%s\n" % (host, timestr))
        fp.close()

