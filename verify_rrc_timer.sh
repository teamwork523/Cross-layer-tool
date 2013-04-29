#!/bin/bash

dir=$1
srv_ip=141.212.113.208
model=$2

for rss in high low; do
    for i in 3 3.5 4 4.5 5; do
        echo "#############################################"
        echo "Running $dir $i $rss..."
        src/traceAnalyzer.py --rrc_timer -l Data/pkt_train/$model/$rss\_rss/*\_$i\_$rss* -d $dir --srv_ip $srv_ip
    done
done
