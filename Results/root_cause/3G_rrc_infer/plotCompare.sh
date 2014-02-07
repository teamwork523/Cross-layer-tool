#!/bin/bash

# plot the lower layer feature vs expected delay

input=$1
yaxis=$2
dataCol=$3
output=$4
./boxPlotConverter.py 1 $dataCol y < $input > tmp.txt
xwidth=$(echo $(tail -n 1 tmp.txt | cut -d"	" -f1) + 0.5 | bc)
gnuplot -p <<EOF
# Data columns:X Min 1stQuartile Median 3rdQuartile Max
set terminal postscript eps color "Helvetica" 18
set output "$output.eps"

# plot transmission delay
set multiplot layout 2,1
set bars 3.0
set style fill empty
set xrange[-0.5:$xwidth]
set xtic 1
set key font ", 16"
#set xlabel "Inter-packet Time (s)"
set ylabel "$yaxis"
plot 'tmp.txt' using 1:3:2:6:5 with candlesticks lt 1 lc rgb "red" notitle, \
     ''                 using 1:4:4:4:4 with candlesticks lt 1 lc rgb "red" notitle
#     ''                 using 1:4       with linespoints  notitle

set yrange[0:1500]
set xlabel "Inter-packet Time (s)"
set ylabel "Expected RTT (ms)"
plot 'expected_rtt' using 1:2 with lines lt -1 lc rgb "red" notitle
unset multiplot

EOF
convert -density 300 "$output.eps" "$output.png"
rm -rf tmp.txt 2> /dev/null
