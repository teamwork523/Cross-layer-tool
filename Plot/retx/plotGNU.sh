#!/bin/bash

name=$1
file=$2
rm $name.eps $name-rrc.eps 2> /dev/null
gnuplot -p <<EOF
# scalable
#set terminal jpeg
#set output "$name.jpeg"
set xdata time
set timefmt "%s"
set format x "%M:%S"     # or anything else
set autoscale
set ytic auto                          # set ytics automatically
set xtic auto                          # set xtics automatically
set title 'TCP and RLC retransmission ($file)'
set xlabel "Time (s)"
set ylabel "Retransmission Count"
set style arrow 1 nohead ls 1 lw 5 lt 4 
set style arrow 2 nohead ls 4 lt 2
set style arrow 3 nohead ls 5 lw 3 lt 3 
set style arrow 4 nohead ls 6 lt 5

# P82 (x, y, xdelta, ydelta)
plot "$file.txt" using 1:(0):(0):2 with vectors arrowstyle 1 title "TCP", \
     "$file.txt" using 1:(0):(0):3 with vectors arrowstyle 2 title "RLC UL", \
     "$file.txt" using 1:(0):(0):4 with vectors arrowstyle 3 title "RLC DL"
#    "$file.txt" using 1:(0):(0):6 with vectors arrowstyle 4 title "IP Packets"
EOF
gnuplot -p << EOF
# scalable
#set terminal postscript eps color
#set terminal jpeg
#set output "$name-rrc.jpeg"
set xdata time
set timefmt "%s"
set format x "%M:%S"     # or anything else
set autoscale
set xtic auto                          # set xtics automatically
set ytic auto                          # set ytics automatically
set title 'RRC State ($file)'
set xlabel "Time (s)"
set ylabel "FACH (2), DCH (3), PCH (4)"
set palette defined (2 "blue", 3 "red", 4 "green")
set style arrow 1 nohead palette

# P82 (x, y, xdelta, ydelta)
plot "$file.txt" using 1:(0):(0):5:5 with vectors arrowstyle 1 title "RRC State"
EOF
#evince $name.eps & evince $name-rrc.eps
