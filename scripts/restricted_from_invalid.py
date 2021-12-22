#!/usr/bin/env python3
import os
import sys
import logging

warn = logging.getLogger("denyfileutil").warning


def show_restricted_usernames(keys, user_dict):
    i = 0
    for key in keys:
        usernames = user_dict.get(key)
        for user in usernames:
            i += 1
            print(f'{user}')
            if i >= num:
                break
        if i >= num:
            break


def get_work_dir() -> str:
    workdir = None
    try:
        workdir = sys.argv[1]
    except IndexError:
        msg = 'You must specify your DenyHosts WORK_DIR'
        print(msg)
        warn(msg)
        usage()
    return workdir


def get_max_displayed() -> int:
    maxdisplay = 10
    if 2 in sys.argv:
        maxdisplay = int(sys.argv[2])
    return maxdisplay


def usage():
    program = sys.argv[0]
    print(f'{program} WORK_DIR [num_results]')
    sys.exit(1)


if __name__ == '__main__':

    work_dir = get_work_dir()
    num = get_max_displayed()
    fname = os.path.join(work_dir, 'users-invalid')

    if not os.path.exists(fname):
        print(f'{fname} does not exist')
        sys.exit(1)

    user_dict = {}

    try:
        with open(fname) as fp:
            for line in fp.readlines():
                try:
                    line_list = line.split(':')
                    username = line_list[0]
                    attempts = int(line_list[1])
                    # timestamp = line_list[2].strip()
                except IndexError as ie:
                    warn(f'File: {fname} missing index on line {line}')
                    continue
                except Exception:
                    continue

                ip_attempts = user_dict['attempts'], []
                ip_attempts.append(username)
                user_dict[attempts] = ip_attempts
    except IOError as ioe:
        iomsg = f'Error when attempting to read from {fname}. Error: {ioe}')
        print(iomsg)
        warn(iomsg)
        sys.exit(1)

    keys = user_dict.keys()
    sorted(keys).reverse()

    show_restricted_usernames(keys, user_dict)
