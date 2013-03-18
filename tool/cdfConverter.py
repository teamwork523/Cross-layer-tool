#!/usr/bin/env python

import sys, math

def Usage():
    print sys.argv[0] + " col accurancy header < filepath, where accurancy is in unit of %"

def main():
    if (len(sys.argv) == 2 and sys.argv[1] == "-h") or len(sys.argv) != 4:
        Usage()
        sys.exit(1)
    
    data = []
    index = int(sys.argv[1]) - 1 
    accurancy = float(sys.argv[2])
    DEL = "\t"
    
    line = sys.stdin.readline()
    while line != "":
        tempData = line.strip().split(DEL)
        data.append(float(tempData[index]))
        line = sys.stdin.readline()
    
    data.sort()
    dataLen = len(data)
    i = 0.0
    while i < 100.0:
        i += accurancy        
        print "%f\t%f" % (i/100.0, data[min(int(i*dataLen/100.0), dataLen-1)])
        

if __name__ == "__main__":
    main()
