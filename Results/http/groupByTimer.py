#!/usr/bin/env python
import sys, math

# group the result based on timer value, i.e. [a, a+1) belongs to the same group

def getMedian(li):
    # assume li sorted
    length = len(li)

    if length == 0:
        return None
    elif length == 1:
        return li[0]

    if length % 2 == 0:
        return float(li[int(length / 2)] + li[int(length / 2) - 1]) / 2.0
    else:
        return float(li[int(length / 2)])

def Usage():
    print sys.argv[0] + " group_col(x) data_col(y) header < filepath"

def main():
    DEL = "\t"

    if (len(sys.argv) == 2 and sys.argv[1] == "-h") or len(sys.argv) != 4:
        Usage()
        sys.exit(1)

    group_col = int(sys.argv[1]) - 1
    data_col = int(sys.argv[2]) - 1
    group_set = set()
    dataMap = {}

    while True:
        line = sys.stdin.readline()
        if not line: break
        curData = line.strip().split()
        group = 0
        data = 0.0
        try:
            data = float(curData[data_col])
            group = int(float(curData[group_col]))
            group_set.add(group)
        except ValueError:
            print >> sys.stderr, "ValueError detected: " + line

        if not dataMap.has_key(group):
            dataMap[group] = []

        dataMap[group].append(data)

    # print the results
    sortedGroup = sorted(group_set)
    for i in range(len(sortedGroup)):
        group = sortedGroup[i]
        line = str(group) + DEL + str(i+0.5) + DEL
        if len(dataMap[group]) > 0:
            data_len = len(dataMap[group])
            sortedData = sorted(dataMap[group])
            myMedian = getMedian(sortedData)
            myLower = sortedData[int(data_len*0.05)]
            myUpper = sortedData[int(data_len*0.95)]
        else:
            myMedian = 0.0
            myLower = 0.0
            myUpper = 0.0
        line += str(myMedian) + DEL + str(myLower) + DEL + str(myUpper) + DEL
        print line.strip()

if __name__ == "__main__":
    main()
