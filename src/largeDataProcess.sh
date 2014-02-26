#!/bin/bash

input=$1

if [[ $input == "-h" ]];then
    echo "./largeDataProcess.sh input output num_of_partitions options(not include -f)"
    exit 1
fi

output=$2
partition=$3
shift 3
options=$@

# profile the data
echo "Start Profiling ..."
time src/traceAnalyzer.py -f $input --large_file --partition $partition

# currently
rm -rf $output 2> /dev/null

i=1
while (( $i <= $partition ));do
    echo "Start partition #$i ..."
    time src/traceAnalyzer.py -f $input --large_file $options >> $output
    i=$(($i + 1))
done

rm -rf profile.txt 2> /dev/null
