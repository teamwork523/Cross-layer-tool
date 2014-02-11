#!/bin/bash

# plot the lower layer feature vs expected delay

input=$1
dataColFile1=$2
dataColFile2=$3
output=$4
# get the intermediate results for first and second plot
./boxPlotConverter.py 1 $dataColFile1 y < $input > tmp1.txt
./boxPlotConverter.py 1 $dataColFile2 y < $input > tmp2.txt
xwidth=$(echo $(tail -n 1 tmp1.txt | cut -d"	" -f1) + 0.5 | bc)
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
set ylabel "UDP RTT (ms)"
plot 'tmp2.txt' using 1:(\$3*1000):(\$2*1000):(\$6*1000):(\$5*1000) with candlesticks lt 2 lc rgb "blue" notitle, \
     ''                 using 1:(\$4*1000):(\$4*1000):(\$4*1000):(\$4*1000) with candlesticks lt 2 lc rgb "blue" notitle
#plot 'tmp2.txt' using 1:3:2:6:5 with candlesticks lt 2 lc rgb "blue" notitle,
#     ''         using 1:4:4:4:4 with candlesticks lt 2 lc rgb "blue" notitle

# plot UDP RTT
set bars 3.0
set style fill empty
set xrange[-0.5:$xwidth]
set xtic 1
set key font ", 16"
set xlabel "Inter-packet Time (s)"
set ylabel "Normalized RLC\nTransmission Delay(ms)"
plot 'tmp1.txt' using 1:3:2:6:5 with candlesticks lt 1 lc rgb "red" notitle, \
     ''         using 1:4:4:4:4 with candlesticks lt 1 lc rgb "red" notitle
unset multiplot

EOF
convert -density 300 "$output.eps" "$output.png"
#rm -rf tmp*.txt 2> /dev/null
