#!/usr/bin/env python
import os
import sys
import logging

warn = logging.getLogger("denyfileutil").warning


def show_restricted_usernames():
    i = 0
    for key in keys:
        usernames = user_dict.get(key)
        for user in usernames:
            i += 1
            print('{0}'.format(user))
            if i >= num:
                break
        if i >= num:
            break


def get_work_dir():
    workdir = None
    try:
        workdir = sys.argv[1]
    except IndexError:
        msg = 'You must specify your DenyHosts WORK_DIR'
        print(msg)
        warn(msg)
        usage()
    return workdir


def get_max_displayed():
    maxdisplay = 10
    if 2 in sys.argv:
        maxdisplay = int(sys.argv[2])
    return maxdisplay


def usage():
    print('{0} WORK_DIR [num_results]'.format(sys.argv[0]))
    sys.exit(1)


work_dir = get_work_dir()
num = get_max_displayed()
fname = os.path.join(work_dir, 'users-invalid')

if os.path.exists(fname) is False:
    print('{0} does not exist'.format(fname))
    sys.exit(1)

user_dict = {}

try:
    with open(fname, 'r') as fp:
        for line in fp:
            try:
                line_list = line.split(':')
                username = line_list[0]
                attempts = int(line_list[1])
                # timestamp = line_list[2].strip()
            except IndexError as ie:
                warn('File: {} missing index on line {}'.format(fname, line))
                continue
            except Exception:
                continue

            if hasattr(user_dict, 'get') and callable(getattr(user_dict, 'get')):  # python 2
                ip_attempts = user_dict.get(attempts, [])
            else:
                # method get doesn't exist in Python 3
                ip_attempts = user_dict['attempts'], []

            ip_attempts.append(username)
            user_dict[attempts] = ip_attempts
except IOError as ioe:
    iomsg = 'Error when attempting to read from {0}. Error: {1}'.format(fname, ioe)
    print(iomsg)
    warn(iomsg)
    sys.exit(1)

keys = user_dict.keys()

if isinstance(keys, list):  # python 2
    keys.sort()
    keys.reverse()
else:  # python 3
    sorted(keys).reverse()

show_restricted_usernames()
