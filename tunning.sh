#!/bin/bash

dir=$1
srv_ip=141.212.113.208
retx_type=$2
# ptof_timer=$3
# ftod_timer=$4
rm result_$retx_type 2> /dev/null
#for i in 1 2 3 4 5
#for i in 1 
#do
    if [ $dir == "uplink" ];then
        para=up
    elif [ $dir == "downlink" ]; then
        para=down
    else
        echo "Need to specifiy direction as first parameter"
        exit 1
    fi
    for ptof_timer in 2
    do
        for ftod_timer in 1.6 1.7 1.8 1.9 2.0 2.1 2.2 2.3 2.4 2.5
        do
            echo "$ftod_timer ################" >> result_$retx_type
            for i in 1 2 3 4 5; do
                echo "Running $dir $i ..."
                echo "FACH_DCH PCH_DCH"
                echo "$ftod_timer $ptof_timer" | tee -a result_$retx_type
                src/traceAnalyzer.py --retx_analysis -l ~/Dropbox/School/Mich/TMobiperf/Data/ReTx_packetTrain/$dir/*$dir\_$i* -d $para --srv_ip $srv_ip --print_retx $retx_type --ptof_timer $ptof_timer --ftod_timer $ftod_timer | tee -a result_$retx_type
            done
        done
    done
#done
