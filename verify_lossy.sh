#!/bin/bash

dir=$1
srv_ip=141.212.113.208
for model in HTC S3; do
    for i in 10 15 20 30; do
        echo "#############################################"
        echo "Running $dir $i $model ..."
        src/traceAnalyzer.py --loss_analysis -l Data/UDP_rrc_inference/$model/*repeat_$i* -d $dir --srv_ip $srv_ip
    done
done
