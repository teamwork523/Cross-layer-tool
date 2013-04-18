#!/bin/bash

USAGE="./push.sh -{o,e}"
OPTION=$1
if [ $# -ne 1 ]
then
    echo $USAGE
    exit 1
fi

owl_folder=/home/haokun/RRC_Analysis_UDP/QCATAnalysis

if [ $OPTION = '-o' ]
then
    scp -r Data/UDP/* haokun@owl.eecs.umich.edu:$owl_folder/Data/UDP/
    scp -r pcap/UDP/* haokun@owl.eecs.umich.edu:$owl_folder/pcap/UDP/
elif [ $OPTION = '-e' ]
then
    scp -r src/* haokun@ep2.eecs.umich.edu:/home/haokun/rrc_analysis/
else
    echo $USAGE
    exit 1
fi

