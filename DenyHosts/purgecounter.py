import logging
import os

from . import constants
from .counter import Counter, CounterRecord

error = logging.getLogger("purgecounter").error
info = logging.getLogger("purgecounter").info


class PurgeCounter(object):
    def __init__(self, prefs):
        self.filename = os.path.join(prefs['WORK_DIR'],
                                     constants.PURGE_HISTORY)
        self.purge_threshold = prefs['PURGE_THRESHOLD']

    def get_banned_for_life(self):
        banned = set()
        if self.purge_threshold == 0:
            return banned

        try:
            fp = open(self.filename, "r")
        except IOError:
            return banned

        for line in fp:
            try:
                host, count, timestamp = line.strip().split(':', 2)
            except Exception:
                continue

            if int(count) > self.purge_threshold:
                banned.add(host)

        fp.close()
        return banned

    def get_data(self):
        counter = Counter()
        try:
            fp = open(self.filename, "r")
        except IOError:
            return counter

        for line in fp:
            try:
                host, count, timestamp = line.strip().split(':', 2)
            except Exception:
                continue
            counter[host] = CounterRecord(int(count), timestamp)

        fp.close()
        return counter

    def write_data(self, data):
        try:
            fp = open(self.filename, "w")
            keys = list(data.keys())
            keys.sort()

            for key in keys:
                fp.write("%s:%s\n" % (key, data[key]))
            fp.close()
        except Exception as e:
            error("error saving %s: %s", self.filename, str(e))

    def increment(self, purged_hosts):
        data = self.get_data()

        for host in purged_hosts:
            data[host] += 1
        self.write_data(data)
