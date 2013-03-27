#!/bin/bash

dir=$1
srv_ip=141.212.113.208
retx_type=$2
for i in 3 3.5 4 4.5 5
do
    if [ $dir == "uplink" ];then
        para=up
    elif [ $dir == "downlink" ]; then
        para=down
    else
        echo "Need to specifiy direction as first parameter"
        exit 1
    fi
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "Running $dir $i ..."
    src/traceAnalyzer.py --retx_analysis --cross_analysis -l Data/pkt_train/*$dir*gap_$i* -d $para --srv_ip $srv_ip --print_retx $2
done
