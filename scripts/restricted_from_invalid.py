#!/usr/bin/env python
import os, sys

def usage():
    print "%s WORK_DIR [num_results]" % sys.argv[0]
    sys.exit(1)

try:
    work_dir = sys.argv[1]
except:
    print "you must specify your DenyHosts WORK_DIR"
    usage()

try: 
    num = int(sys.argv[2])
except:
    num = 10

fname = os.path.join(work_dir, "users-invalid")

try:
    fp = open(fname, "r")
except:
    print fname, "does not exist"
    sys.exit(1)

d = {}

for line in fp:
    try:
        foo = line.split(":")
        username = foo[0]
        attempts = int(foo[1])
        # timestamp = foo[2].strip()
    except:
        continue

    l = d.get(attempts, [])
    l.append(username)
    d[attempts] = l

fp.close()

keys = d.keys()
keys.sort()
keys.reverse()

i = 0
for key in keys:
    l = d.get(key)
    for username in l:
        i += 1
        print username
        if i >= num: break
    if i >= num: break
