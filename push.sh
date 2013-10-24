#!/bin/bash

USAGE="./push.sh -{o,e} -d"
OPTION=$1
UPLOAD_DATA=$2
if [ $# -ne 1 ] && [ $# -ne 2 ];then
    echo $USAGE
    exit 1
fi

owl_folder=/home/haokun/RRC_Analysis_UDP/QCATAnalysis
ep2_folder=/home/haokun/cross-layer
if [ $OPTION = '-o' ]
then
    #scp -r Data/UDP/* haokun@owl.eecs.umich.edu:$owl_folder/Data/UDP/
    scp -r pcap/UDP/seq/* haokun@owl.eecs.umich.edu:$owl_folder/pcap/UDP/seq/
elif [ $OPTION = '-e' ]
then
    #scp -r pcap/UDP/seq/* haokun@ep2.eecs.umich.edu:$ep2_folder/pcap/UDP/seq/
    scp -r src/*.py haokun@ep2.eecs.umich.edu:$ep2_folder/src/
    if [ $UPLOAD_DATA = '-d' ];then
        scp -r data/TCP/*.txt haokun@ep2.eecs.umich.edu:$ep2_folder/data/
    fi
else
    echo $USAGE
    exit 1
fi

