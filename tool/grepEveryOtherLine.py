#!/usr/bin/env python

import sys

def Usage():
    print sys.argv[0] + " start period < filepath"

def main():  
    if (len(sys.argv) == 2 and sys.argv[1] == "-h") or len(sys.argv) != 3:
        Usage()
        sys.exit(1)

    start = int(sys.argv[1])
    period = int(sys.argv[2])

    line = ""
    for i in range(start-1):
        line = sys.stdin.readline()

    while line != "":
        line = sys.stdin.readline().strip()
        if not line:
            break
        print line
        for i in range(period-1):
            line = sys.stdin.readline().strip()
            if not line:
                sys.exit(1)

if __name__ == "__main__":
    main()
