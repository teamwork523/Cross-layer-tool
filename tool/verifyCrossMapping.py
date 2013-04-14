#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   03/28/2013
The script will parse the RAN trace and analyze the 
"""

# TODO: FINISH this

import sys

direction = "Uplink"

class entry:
    def __init__(lines):
        self.content = lines

def main():
    filename = sys.argv[1]
    fp = open(filename)
    tempLines = []
    entryList = []

    while True:
        line = fp.readline().strip()
        if not line:
            break
        if line[0] != "|":
            continue
        if line.find("|BITMASK") == 0:
            if soLine == ""
            if tempLines:
                entryList.append(tempLines)
                

if __name__ == "__main__":
    main()
