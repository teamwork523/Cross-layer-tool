#!/bin/bash
# rm $2 2> /dev/null
folder=$1
ip=$2
src=$3
echo $src
for i in $(ls $folder)
do
    # echo "****************"
    echo $i
    if [ -z "$ip" ]
    then
        src/traceAnalyzer.py -l $folder/$i >> temp.txt
    else
        if [ $src = "src" ]
        then
            src/traceAnalyzer.py --src_ip $ip -l $folder/$i >> temp.txt
            #src/traceAnalyzer.py --src_ip $ip -l $folder/$i 2>> temp.txt
        elif [ $src = "dst" ]
        then
            src/traceAnalyzer.py --dst_ip $ip -l $folder/$i >> temp.txt
            #src/traceAnalyzer.py --dst_ip $ip -l $folder/$i 2>> temp.txt
        else
            echo "must specify src/dst"
        fi
    fi
done
src/transpose.py temp.txt
rm temp.txt
