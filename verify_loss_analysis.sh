#!/bin/bash

# temp script => auto it later
echo "Running Sample rand repeat 1 ... "
src/traceAnalyzer.py -l Data/UDP/Sample/*sample* -p pcap/UDP/*sample* -d up --srv_ip 141.212.113.208 --loss_analysis -t udp
echo "Running HTC rand repeat 10 ... "
src/traceAnalyzer.py -l Data/UDP/HTC/*repeat_10_rand* -p pcap/UDP/*HTC* -d up --srv_ip 141.212.113.208 --loss_analysis -t udp
echo "Running S3 rand repeat 10 ... "
src/traceAnalyzer.py -l Data/UDP/S3/*repeat_10_rand* -p pcap/UDP/*S3* -d up --srv_ip 141.212.113.208 --loss_analysis -t udp
