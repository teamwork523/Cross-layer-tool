#!/usr/bin/env python

# inject a string / data into a specific col in the file
import sys, math

INJECT_DEFAULT = "FACH DCH PCH FACH_PROMOTE PCH_PROMOTE"

def Usage():
    print sys.argv[0] + " col_num inject_content < filepath"
    print "... Column number starts from 1"
    print "... Going to inject before col %d" % (col_num)
    
def main():
    DEL = "\t"

    if (len(sys.argv) == 2 and sys.argv[1] == "-h") or len(sys.argv) > 3 or len(sys.argv) < 2:
        Usage()
        sys.exit(1)

    num_col = int(sys.argv[1]) - 1
    inject_data = INJECT_DEFAULT.split()
    if len(sys.argv) == 3:
        inject_data = str(sys.argv[2]).split()

    for data in inject_data:
        line = sys.stdin.readline()
        if not line: break
        print DEL.join(line.strip().split().insert(num_col, data))

if __name__ == "__main__":
    main()    
