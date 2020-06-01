import logging
import requests
import re

logger = logging.getLogger("my_ip")
debug, info, error, exception = logger.debug, logger.info, logger.error, logger.exception


class MyIp(object):
    def __init__(self, prefs):
        self.__prefs = prefs
        self.__work_dir = prefs.get('WORK_DIR')
        self.__ip_regex = re.compile('(\d{1,3}\.){3}\d{1,3}')
        self.__remote_ips = {}
        self.__remote_apis = [
            'https://api.ipify.org',
            'https://ident.me',
            'https://ipinfo.io/ip',
            'https://checkip.amazonaws.com'
        ]
        self.__remote_parse = [
            'http://checkip.dyndns.org',
            'https://ipchicken.com'
        ]

    def get_remote_ip(self):
        for api in self.__remote_apis:
            try:
                ip = self.__ip_regex.search(requests.get(api).text)
                if ip:
                    ip = ip.group().strip()
                    if ip in self.__remote_ips.keys():
                        self.__remote_ips[ip] = self.__remote_ips[ip] + 1
                    else:
                        self.__remote_ips[ip] = 1
            except:
                pass
        for remote_parse in self.__remote_parse:
            try:
                res = requests.get(remote_parse).text
                ip = self.__ip_regex.search(res)
                if ip:
                    ip = ip.group().strip()
                    if ip in self.__remote_ips.keys():
                        self.__remote_ips[ip] = self.__remote_ips[ip] + 1
                    else:
                        self.__remote_ips[ip] = 1
            except:
                pass
        return self.__remote_ips
