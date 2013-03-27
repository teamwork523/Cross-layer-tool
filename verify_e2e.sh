#!/bin/bash

dir=e2e
srv_ip=141.212.113.208
direction=$1
retx_type=$2

if [ -z $direction ];then
    echo "Direction parameter required!"
    exit 1
fi
if [ $direction == "uplink" ];then
    direction=up
fi
if [ $direction == "downlink" ];then
    direction=down
fi
for i in good bad; do
    for j in new old; do
        echo "Running $dir $i $j ..."
        if [ -z $retx_type ]; then
            src/traceAnalyzer.py --retx_analysis --cross_analysis -l Data/$dir/*$i*$j* -d $direction --srv_ip $srv_ip | tee Debug/debug_$i\_$j.txt
        else
            src/traceAnalyzer.py --retx_analysis --cross_analysis --print_retx $retx_type -l Data/$dir/*$i*$j* -d $direction --srv_ip $srv_ip | tee Debug/debug_$i\_$j.txt            
        fi
    done
done

if [ -n $1 ];then
    if [ $1 == "-v" ]; then
        for i in good bad;  do
            for j in new old; do
                echo "Verifying $i $j ..."
                grep "Retransmission count" Debug/debug_$i\_$j.txt
                check=$(grep "NO" Debug/debug_$i\_$j.txt | wc -l)
                echo $check
                if (( $check > 0 )); then
                    echo "Something wrong, check the code"
                    exit 1
                fi
            done
        done
        echo "LGTM!!!"
    fi
fi
