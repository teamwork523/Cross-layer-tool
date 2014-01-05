#!/bin/bash

input=$1
legend=$2
output=$3
columns=$4

gnuplot -p <<EOF
set terminal postscript eps color "Arial" 21
set output "$output.eps"
set bars 3.0
set style fill empty
set ylabel "RLC Normalized Transmission Delay (ms)"
set xlabel "$legend"
plot '$input' every ::1 using $columns:3 with points lt 6
EOF
convert -density 300 "$output.eps" "$output.png"
