#!/bin/bash
rm $2 2> /dev/null

for i in $(ls $1)
do
    # echo "****************"
    echo $i
   ./traceAnalyzer.py -l $1/$i >> $2 
   # ./traceAnalyzer.py --dst_ip 162.171.132.189 -l $1/$i >> $2
done
