#!/bin/bash

dir=$1
srv_ip=141.212.113.208
retx_type=$2
rss_level=$3
for i in 3 3.5 4 4.5 5
#for i in 4
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
    src/traceAnalyzer.py --retx_analysis --cross_analysis -l Data/pkt_train/HTC/$rss_level\_rss/*$dir*gap_$i\_$rss_level* -d $para --srv_ip $srv_ip --print_retx $2 | tee Result_temp/HTC/$dir\_$i\_$rss_level\_cross_map.txt
done
