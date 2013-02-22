#!/usr/bin/env python

import sys

f = open(sys.argv[1], "r")
rev = {}

while True:
    line = f.readline().strip()
    if not line: break
    data = line.split()
    for i in range(len(data)):
        if i not in rev.keys():
            rev[i] = [data[i]]
        else:
            rev[i].append(data[i])

for i in sorted(rev.keys()):
    print "\t".join(rev[i])
