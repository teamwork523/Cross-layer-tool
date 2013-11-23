#!/bin/bash

input=$1
legend=$2
line_type=$3
gnuplot -p <<EOF
# scalable
#set terminal jpeg
#set output "$name.jpeg"
set terminal postscript eps color "Arial" 21
set output "$input.eps"
set autoscale
set xtic auto                          # set xtics automatically
set ytic auto                          # set ytics automatically
# set title 'CDF of $legend'
set xlabel "$legend"
set ylabel "CDF"

plot "$input.txt" u 2:1 w lines lt $line_type title "$legend"
EOF
