#!/usr/bin/env python

import sys, math

def Usage():
    print sys.argv[0] + " x_col y_col header < filepath"

def sum(li):
    cur = 0.0
    for a in li:
        cur += a
    return cur

def main():
    # delimiter
    DEL = "\t"
    x_data = []
    y_data = []
    total = 0.0

    if (len(sys.argv) == 2 and sys.argv[1] == "-h") or len(sys.argv) != 4:
        Usage()
        sys.exit(1)

    x_index = int(sys.argv[1]) - 1
    y_index = int(sys.argv[2]) - 1

    # check header
    if sys.argv[3] == "y" or sys.argv[3] == "Y":
        header = sys.stdin.readline()

    line = sys.stdin.readline()
    while line != "":
        tempData = line.strip().split(DEL)
        x_data.append(float(tempData[x_index]))
        y_data.append(float(tempData[y_index]))
        line = sys.stdin.readline()
    
    x_sqr_sum = 0.0
    y_sqr_sum = 0.0
    xy_sum = 0.0
    x_bar = sum(x_data)/len(x_data)
    y_bar = sum(y_data)/len(y_data)
    
    for i in range(len(x_data)):
        xy_sum += (x_data[i] - x_bar)*(y_data[i] - y_bar)
        x_sqr_sum += (x_data[i] - x_bar)*(x_data[i] - x_bar)
        y_sqr_sum += (y_data[i] - y_bar)*(y_data[i] - y_bar)
    
    r = xy_sum/(math.sqrt(x_sqr_sum)*math.sqrt(y_sqr_sum)) 
    print r
    
if __name__ == "__main__":
    main()
        
