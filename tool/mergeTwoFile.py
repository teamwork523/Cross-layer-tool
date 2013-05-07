#!/usr/bin/env python

import sys, math

# append two files if both first cols are the same, append the non common cols
# otherwise append everything the raw by raw

def Usage():
    print sys.argv[0] + " file1 file2"

def main():
    # delimiter
    DEL = "\t"
    
    if (len(sys.argv) == 2 and sys.argv[1] == "-h") or len(sys.argv) != 3:
        Usage()
        sys.exit(1)

    f1 = open(sys.argv[1])
    f2 = open(sys.argv[2])

    while True:
        file1_line = f1.readline()
        file2_line = f2.readline()
        if (not file1_line) or (not file2_line):
            break
        l1 = file1_line.strip().split()
        l2 = file2_line.strip().split()
        
        if l1[0] != l2[0]:
            print DEL.join(l1 + l2)
        else:
            print DEL.join(l1 + l2[1:])


if __name__ == "__main__":
    main()
