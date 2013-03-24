#!/bin/bash

dir=e2e
srv_ip=141.212.113.208
for i in good bad; do
    for j in new old; do
        echo "Running $dir $i $j ..."
        src/traceAnalyzer.py --retx_analysis --cross_analysis -l Data/$dir/*$i*$j* -d up --srv_ip $srv_ip | tee Debug/debug_$i\_$j.txt
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
