#!/bin/bash

USAGE="./push.sh -{o,e} -{d,p}"
OPTION=$1
UPLOAD_DATA=$2
if [ $# -ne 1 ] && [ $# -ne 2 ];then
    echo $USAGE
    exit 1
fi
prj_folder=/home/teamwork523/Desktop/UMich/Cross-layer/Analysis
owl_folder=/home/haokun/RRC_Analysis_UDP/QCATAnalysis
ep2_folder=/home/haokun/cross-layer
if [ $OPTION = '-o' ]
then
    #scp -r Data/UDP/* haokun@owl.eecs.umich.edu:$owl_folder/Data/UDP/
    scp -r $prj_folder/pcap/UDP/seq/* haokun@owl.eecs.umich.edu:$owl_folder/pcap/UDP/seq/
elif [ $OPTION = '-e' ]
then
    #scp -r pcap/UDP/seq/* haokun@ep2.eecs.umich.edu:$ep2_folder/pcap/UDP/seq/
    scp -r $prj_folder/src/*.py haokun@ep2.eecs.umich.edu:$ep2_folder/src/
    if [[ -n $UPLOAD_DATA ]] && [ $UPLOAD_DATA = '-d' ];then
        #scp -r $prj_folder/data/TCP/*.txt haokun@ep2.eecs.umich.edu:$ep2_folder/data/TCP/
        # Root cause analysis
        #scp -r $prj_folder/data/UDP/Root_cause/11-18.07-30_root_cause_rrc_infer_3G_whole_night.txt haokun@ep2.eecs.umich.edu:$ep2_folder/data/UDP/Root_cause/
        #scp -r $prj_folder/data/Verify/* haokun@ep2.eecs.umich.edu:$ep2_folder/data/Verify/
        scp -r $prj_folder/data/App/WCDMA/browsing/12-22.21-09_browsing_5s_repeat_50.zip  haokun@ep2.eecs.umich.edu:$ep2_folder/data/App/WCDMA/browsing/
    fi
    if [[ -n $UPLOAD_DATA ]] && [ $UPLOAD_DATA = '-p' ];then
        scp -r $prj_folder/data/PCAP/*.pcap haokun@ep2.eecs.umich.edu:$ep2_folder/data/PCAP/
    fi
else
    echo $USAGE
    exit 1
fi

