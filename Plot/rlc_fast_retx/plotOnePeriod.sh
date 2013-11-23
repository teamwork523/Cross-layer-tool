#!/bin/bash

file=$1
tit=$2
gnuplot -p << EOF
# scalable
#set xdata time
#set timefmt "%s"     # unix timestamp
#set format x "%S"    # or anything else
#set term pngcairo dashed
set termoption dashed   # enable dashed line
set autoscale
#set xtic auto                          # set xtics automatically
#set ytic auto                          # set ytics automatically
set title '$tit'
set xlabel "Time (ms)"
set ylabel "RLC Sequence Number"
#set grid
set palette defined $color
set style arrow 1 head ls 4 lw 1
set style arrow 2 nohead ls 21 lw 1

plot "$file" using 1:(0):(0):(\$3 > 0 ? \$3 : 1/0) with vectors arrowstyle 2 title "RLC PDUs", \
     "" using 1:(0):(0):(\$2 > 0 ? \$2 : 1/0) with vectors arrowstyle 1 title "Dup ACKs"
EOF
