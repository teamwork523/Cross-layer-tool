#!/bin/bash

name=$1
file=$2
gnuplot -p <<EOF
# scalable
set terminal postscript eps color
set output "$name.eps"
set xdata time
set timefmt "%s"
set format x "%S"     # or anything else
set autoscale
set xtic auto                          # set xtics automatically
set ytic auto                          # set ytics automatically
set title 'Link layer retrans vs Trans layer retrans $file'
set xlabel "Time (s)"
set ylabel "Retransmission Data (Bytes)"
set style arrow 1 heads ls 1 lt 2 
set style arrow 2 nohead ls 2 lt 3
set style arrow 3 nohead ls 3 lt 4 

# P82 (x, y, xdelta, ydelta)
plot "$file.txt" using 1:(0):(0):2 with vectors arrowstyle 1 title "Transport Layer", \
     "$file.txt" using 1:(0):(0):3 with vectors arrowstyle 2 title "RLC UL", \
     "$file.txt" using 1:(0):(0):4 with vectors arrowstyle 3 title "RLC DL"
EOF
gnuplot -p << EOF
# scalable
set terminal postscript eps color
set output "$name-rrc.eps"
set xdata time
set timefmt "%s"
set format x "%S"     # or anything else
set autoscale
set xtic auto                          # set xtics automatically
set ytic auto                          # set ytics automatically
set title 'RRC State'
set xlabel "Time (s)"
set ylabel "FACH (2), DCH (3), PCH (4)"
set palette defined (2 "blue", 3 "red", 4 "green")
set style arrow 1 nohead palette

# P82 (x, y, xdelta, ydelta)
plot "$file.txt" using 1:(0):(0):5:5 with vectors arrowstyle 1 title "RRC State"
EOF
evince $name.eps & evince $name-rrc.eps
