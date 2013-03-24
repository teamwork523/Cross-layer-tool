#!/bin/bash

USAGE="./push.sh -{o,e}"
OPTION=$1
if [ $# -ne 1 ]
then
    echo $USAGE
    exit 1
fi

if [ $OPTION = '-o' ]
then
    scp -r src/* haokun@owl.eecs.umich.edu:/home/haokun/rrc_analysis/
elif [ $OPTION = '-e' ]
then
    scp -r src/* haokun@ep2.eecs.umich.edu:/home/haokun/rrc_analysis/
else
    echo $USAGE
    exit 1
fi

