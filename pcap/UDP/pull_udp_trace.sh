#!/bin/bash
folder=$1
mkdir $folder 2> /dev/null
scp -r haokun@ep2.eecs.umich.edu:/home/haokun/RRC_server/pcap/$folder/ .
