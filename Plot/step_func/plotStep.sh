#!/bin/bash

# set terminal pngcairo  transparent enhanced font "arial,10" fontscale 1.0 size 500, 350 
# set output 'steps.1.png'
gnuplot -p << EOF
set title "Step functions" 
set termoption dashed 
set xrange[-1:7]
set yrange[-1:9]
#set style line 1 lc rgb '#0060ad' lt 1 lw 2 pt 7 pi -1 ps 1.5
#set pointintervalbox 4

plot "steps.dat" using 1:2 notitle with lines ls 3 lw 4
EOF
