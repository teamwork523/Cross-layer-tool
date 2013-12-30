#!/bin/bash

input=$1
legend=$2
gnuplot -p <<EOF
# Data columns:X Min 1stQuartile Median 3rdQuartile Max
set terminal postscript eps color "Arial" 21
set output "$input.eps"
set bars 3.0
set style fill empty
set xlabel "Inter-packet Time (s)"
set ylabel "$legend"
#plot '$input.txt' using 1:3:2:6:5 with candlesticks lt 4 title '$legend', \
#     ''                 using 1:4:4:4:4 with candlesticks lt 3 notitle
#     ''                 using 1:4       with linespoints  notitle
plot '$input.txt' using 1:4:2:6:(0.25) with boxerrorbars lc 1 lw 4 title "$legend"
EOF
convert -density 300 "$input.eps" "$input.png"
