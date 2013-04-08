#!/bin/bash

dir=$1
srv_ip=141.212.113.208
model=$2
rss=$3
for i in 3 3.5 4 4.5 5
do
    echo "Running $dir $i ..."
    src/traceAnalyzer.py --verify_cross_analysis -l Data/pkt_train/$model/$rss\_rss/*$i\_$rss* -d $dir --srv_ip $srv_ip
done
