#!/bin/bash

folder=$1
if [ $folder == "TCP" ]; then
    unit="packet"
else
    unit="PDU"
fi
file1=3.5
file2=4
file3=4.5
file4=5
gnuplot -p <<EOF
# scalable
#set terminal jpeg
#set output "$name.jpeg"
set autoscale
set xtic auto                          # set xtics automatically
set ytic auto                          # set ytics automatically
set title 'Promotion Delay Effect of $1'
set xlabel "The delay (s) between start of FACH state to the first $1 $unit"
set ylabel "CDF"

plot "$folder/uplink_gap_$file1\_cdf" u 2:1 w lines lt 2 title "$file1\s gap", \
     "$folder/uplink_gap_$file2\_cdf" u 2:1 w lines lt 3 title "$file2\s gap", \
     "$folder/uplink_gap_$file3\_cdf" u 2:1 w lines lt 4 title "$file3\s gap", \
     "$folder/uplink_gap_$file4\_cdf" u 2:1 w lines lt 5 title "$file4\s gap"
EOF
