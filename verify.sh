#!/bin/bash

dir=$1
srv_ip=141.212.113.208
retx_type=$2
for i in 1 2 3 4 5
do
    if [ $dir == "uplink" ];then
        para=up
    elif [ $dir == "downlink" ]; then
        para=down
    else
        echo "Need to specifiy direction as first parameter"
        exit 1
    fi
    echo "Running $dir $i ..."
    if [ -z $retx_type ]; then
        src/traceAnalyzer.py --retx_analysis -l ~/Dropbox/School/Mich/TMobiperf/Data/ReTx_packetTrain/$dir/*$dir\_$i* -d $para --srv_ip $srv_ip --cross_map
    else
        src/traceAnalyzer.py --retx_analysis -l ~/Dropbox/School/Mich/TMobiperf/Data/ReTx_packetTrain/$dir/*$dir\_$i* -d $para --srv_ip $srv_ip --print_retx $retx_type --cross_map
    fi
done
