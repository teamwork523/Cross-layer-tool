#!/usr/bin/python

import sys

f = open(sys.argv[1])
start = int(sys.argv[2])
gap = int(sys.argv[3])
lines = [i.strip() for i in f.readlines()]
for rt in lines[start::gap]:
    print rt
