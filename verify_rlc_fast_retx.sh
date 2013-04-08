#!/bin/bash

dir=$1
srv_ip=141.212.113.208
model=$2
dup_ack_num=$3
for rss in high low; do
    for i in 3 3.5 4 4.5 5; do
        echo "#############################################"
        echo "Running $dir $i $rss..."
        src/traceAnalyzer.py --retx_analysis --cross_analysis --dup_ack_threshold $dup_ack_num -l Data/pkt_train/$model/$rss\_rss/*$i\_$rss* -d $dir --srv_ip $srv_ip
    done
done
