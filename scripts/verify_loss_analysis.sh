#!/bin/bash

dir=$1
srv_ip=141.212.113.208
model=$2

for i in 10 15 20 25 30; do
    echo "############################################"
    echo "Runing $model $i ..."
    src/traceAnalyzer.py -l Data/UDP/$model/seq/*repeat_$i* -p pcap/UDP/seq/$model/*repeat_$i* -d $dir --srv_ip $srv_ip --loss_analysis -t udp
done
