#!/usr/bin/env python
import sys, math

# convert excel type of data into box err bar type (mean std mean std)

def Usage():
    print sys.argv[0] + " num_col num_group < filepath"
    print "Sample Data: "
    print "1: group1_col1  group1_col2"
    print "2: group1_col1  group1_col2"
    print "1: group2_col1  group2_col2"
    print "2: group2_col1  group2_col2"

# create a map between col_id to that col of data
def create_single_group(num_col):
    single_group = {}
    for i in range(num_col):
        single_group[i] = []
    return single_group

# calculate the standard deviation of the data
def cal_std (data, mean):
    diff_sum = 0.0
    for ele in data:
        diff_sum += (ele-mean)*(ele-mean)
    return math.sqrt(diff_sum / len(data))

def main():
    DEL = "\t"
    data = []

    if (len(sys.argv) == 2 and sys.argv[1] == "-h") or len(sys.argv) != 3:
        Usage()
        sys.exit(1)

    num_col = int(sys.argv[1])
    num_group = int(sys.argv[2])

    # read data
    raw_data = []   
    while True:
        line = sys.stdin.readline()
        if not line: break
        raw_data.append(line.strip().split(DEL))

    # convert data into groups of cols
    cur_row = 0
    num_row = len(raw_data) / num_group
    cur_group = None
    for i in range(num_row)*num_group:
        if i == 0:
            cur_group = create_single_group(num_col)
        cur_data = raw_data.pop(0)
        for j in range(num_col):
            cur_group[j].append(float(cur_data[j]))
        if i == num_row - 1:
            data.append(cur_group)
    
    # generate the boxErrorBar plot result
    # format:
    #   col_id  group1_mean group1_delta    group2_mean group2_delta
    for i in range(num_col):
        line = str(i+0.5) + "\t"
        for group_id in range(num_group):
            mean = float(sum(data[group_id][i]))/float(len(data[group_id][i]))
            line += str(mean) + "\t" + str(cal_std(data[group_id][i], mean)) + "\t"
        print line.strip()

if __name__ == "__main__":
    main()






