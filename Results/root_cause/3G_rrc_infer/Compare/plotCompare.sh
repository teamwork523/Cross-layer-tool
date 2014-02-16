#!/bin/bash

# plot the lower layer feature vs expected delay

input=$1
dataColUDP=$2
dataColDemo=$3
dataColIPtoRLC=$4
output=$5
# get the intermediate results for first and second plot
../boxPlotConverter.py 1 $dataColUDP y < $input > tmp_udp.txt
../boxPlotConverter.py 1 $dataColDemo y < $input > tmp_demotion.txt
../boxPlotConverter.py 1 $dataColIPtoRLC y < $input > tmp_IP_to_first_RLC_PDU.txt
xwidth=$(echo $(tail -n 1 tmp_udp.txt | cut -d"	" -f1) + 0.5 | bc)
gnuplot -p <<EOF
# Data columns:X Min 1stQuartile Median 3rdQuartile Max
set terminal postscript eps color "Helvetica" 18
set output "$output.eps"

# plot UDP RTT
set multiplot layout 2,1
set bars 3.0
set style fill empty
set xrange[-0.5:$xwidth]
set xtic 1
set key font ", 16"
set ylabel "Upper layer latency (ms)"
# 1:(\$3*1000):(\$2*1000):(\$6*1000):(\$5*1000)
# 1:(\$4*1000):(\$4*1000):(\$4*1000):(\$4*1000)
# 1:3:2:6:5
# 1:4:4:4:4
plot 'tmp_udp.txt' using 1:(\$3*1000):(\$2*1000):(\$6*1000):(\$5*1000) with candlesticks lt 1 lc rgb "blue" title "UDP RTT", \
     ''                 using 1:(\$4*1000):(\$4*1000):(\$4*1000):(\$4*1000) with candlesticks lt 1 lc rgb "blue" notitle

# plot Lower layer features
set bars 3.0
set style fill empty
set xrange[-0.5:$xwidth]
set xtic 1
set key font ", 14"
set xlabel "Inter-packet Time (s)"
set ylabel "Lower layer latency (ms)"
#set y2label "Y2: IP to first RLC PDU delay (ms)"
set ytics nomirror
plot 'tmp_demotion.txt' using 1:(\$3*1000):(\$2*1000):(\$6*1000):(\$5*1000) with candlesticks ls 2 lc rgb "red" fs pattern 4 title "DCH_to_FACH demotion delay", \
     ''         using 1:(\$4*1000):(\$4*1000):(\$4*1000):(\$4*1000) with candlesticks lt 2 lc rgb "red" notitle, \
     'tmp_IP_to_first_RLC_PDU.txt' using 1:(\$3*1000):(\$2*1000):(\$6*1000):(\$5*1000) with candlesticks ls 1 lc rgb "green" fs pattern 5 title "Cross-layer transmission delay", \
     ''         using 1:(\$4*1000):(\$4*1000):(\$4*1000):(\$4*1000) with candlesticks lt 1 lc rgb "green" notitle

unset multiplot

EOF
convert -density 300 "$output.eps" "$output.png"
rm -rf tmp*.txt 2> /dev/null
