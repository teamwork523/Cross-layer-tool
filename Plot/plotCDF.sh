#!/bin/bash

input=$1
legend=$2
gnuplot -p <<EOF
# scalable
#set terminal jpeg
#set output "$name.jpeg"
set autoscale
set xtic auto                          # set xtics automatically
set ytic auto                          # set ytics automatically
# set title 'CDF of $legend'
set xlabel "$legend"
set ylabel "CDF"

plot "$input.txt" u 2:1 w lines lt 4 title "$legend"
EOF
