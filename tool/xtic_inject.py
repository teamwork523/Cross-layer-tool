#!/usr/bin/env python

# inject a string / data into a specific col in the file
import sys, math

INJECT_DEFAULT = 'FACH\\nINIT DCH PCH\\nINIT FACH\\nPROMOTE PCH\\nPROMOTE'

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
    if num_col < 0:
        num_col = 0
    inject_data = INJECT_DEFAULT.split(" ")
    if len(sys.argv) == 3:
        inject_data = str(sys.argv[2]).split()

    for data in inject_data:
        line = sys.stdin.readline()
        if not line: break
        cur_data = line.strip().split()
        cur_data.insert(num_col, data)
        print DEL.join(cur_data)

if __name__ == "__main__":
    main()    
