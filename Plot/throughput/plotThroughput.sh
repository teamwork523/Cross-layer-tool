#!/bin/bash

input=$1
legend=$2
# rm $name.eps $name-rrc.eps 2> /dev/null
grep "	2$" $input.txt > $input-2.txt
grep "	3$" $input.txt > $input-3.txt
gnuplot -p <<EOF
# scalable
#set terminal jpeg
#set output "$name.jpeg"
set xdata time
set timefmt "%s"
set format x "%M:%S"     # or anything else
set autoscale
set xtic auto                          # set xtics automatically
set ytic auto                          # set ytics automatically
set title 'Throughput vs RRC state ($legend)'
set xlabel "Time (s)"
set ylabel "Throughput (bps)"
set palette defined ( 2 "blue", 3 "red", 4 "green")

# P82 (x, y, xdelta, ydelta)
plot "$input-2.txt" u 1:2:3 w linespoints lt 4 title "FACH",\
     "$input-3.txt" u 1:2:3 w linespoints lt 5 title "DCH"
EOF
