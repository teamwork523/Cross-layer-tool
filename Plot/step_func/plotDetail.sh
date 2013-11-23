#!/bin/bash

file=$1
#tit=$2
gnuplot -p << EOF
set terminal postscript eps color "Arial" 20
set output "$file.eps"
set termoption dashed   # enable dashed line
set xrange [-200:5200]
set yrange [0:6.5]
set key box 
set key width -2
set key samplen 4
set key font ",15"
#set key in vert
set key top center                         # move the legend outside
set xlabel "Time (ms)"
set ylabel "RRC Subtates\nPCH_INIT(1), PCH_PROMOTE(2), FACH_INIT(3)\nFACH_STABLE(4), FACH_PROMOTE(5), DCH (6)"
#set grid
set style arrow 1 head lt 2 lc rgb "#FC0FC0" lw 4 # pink
set style arrow 3 heads ls 5 lc rgb "blue" lw 2
#set style arrow 2 nohead lt 6 lw 1
set style line 2 lt 1 lc rgb "green" lw 8
set style line 4 lt 1 lc rgb "red" lw 2

plot "$file\_TCP.txt" using 1:(0):(0):5 with vectors arrowstyle 1 title "TCP Packets", \
     "$file\_RLC.txt" using 1:(0):(0):5 with vectors linestyle 2 nohead title "RLC PDUs", \
     "$file\_DUP_ACK.txt" using 1:(0):(0):5 with vectors arrowstyle 3 title "RLC Dup ACKs", \
     "$file\_state_trans.txt" using 1:2 with linespoints linestyle 4 title "RRC Transitions"
EOF
