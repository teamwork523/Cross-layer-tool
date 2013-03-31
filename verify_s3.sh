#!/bin/bash

dir=$1
srv_ip=141.212.113.208
retx_type=$2
rss=$3
for i in 3 3.5 4 4.5 5
do
    if [ $rss != "high" ] && [ $rss != "low" ];then
        echo "Either high or low RSS is required"
        exit 1
    fi
    
    if [ $dir == "uplink" ];then
        dir=up
    elif [ $dir == "downlink" ]; then
        dir=down
    fi
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "Running $dir $i with $rss RSS..."
    src/traceAnalyzer.py --retx_analysis --cross_analysis -l Data/S3/$rss\_rss/*$i* -d $dir --srv_ip $srv_ip --print_retx $2 | tee Result_temp/s3/S3_$i\_$rss.txt
done
