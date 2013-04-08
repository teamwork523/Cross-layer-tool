#!/bin/bash

dir=$1
srv_ip=141.212.113.208
dup_ack_th=$2
model=$3
for rss_level in high low; do
    for i in 3 3.5 4 4.5 5
    do
        if [ $dir == "uplink" ];then
            para=up
        elif [ $dir == "downlink" ]; then
            para=down
        else
            para=$dir
        fi
        echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        echo "Running $dir $model $rss_level $i ..."
        src/traceAnalyzer.py --retx_analysis --cross_analysis -l Data/pkt_train/$model/$rss_level\_rss/*$dir*gap_$i\_$rss_level* -d $para --srv_ip $srv_ip --dup_ack_threshold $dup_ack_th
    done
done
