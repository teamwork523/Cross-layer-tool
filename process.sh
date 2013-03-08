#!/bin/bash
# rm $2 2> /dev/null
folder=$1
dir=$3
echo $src
filename=$2
if [ -z "$filename" ]
then
    echo "No Destination filename specified"
    exit 1
fi

dst=Plot/energy
count=1
for i in $(ls $folder)
do
    # echo "****************"
    echo $i
    if [ -z "$ip" ]
    then
        src/traceAnalyzer.py -l $folder/$i > $dst/$filename$count.txt 2>> temp.txt
    else
        if [ -z "$dir" ];then
            echo "No direction specified"
            exit 1
        fi
        if [ $src = "src" ]
        then
            src/traceAnalyzer.py --src_ip $ip -l $folder/$i -d $dir > $dst/$filename$count.txt 2>> temp.txt
        elif [ $src = "dst" ]
        then
            src/traceAnalyzer.py --dst_ip $ip -l $folder/$i -d $dir > $dst/$filename$count.txt 2>> temp.txt
        else
            echo "must specify src/dst"
            exit 1
        fi
    fi
    (( count+=1 ))
done
src/transpose.py temp.txt
rm temp.txt
