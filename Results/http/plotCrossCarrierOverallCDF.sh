#!/bin/bash

data_col=$1
att_file=$2
tmobile_file=$3
output=$4
# Generate CDF plot
Tools/plot/cdfConverter.py $data_col 1 n < $att_file > att_cdf
Tools/plot/cdfConverter.py $data_col 1 n < $tmobile_file > tmobile_cdf
Tools/common/mergeTwoFile.py att_cdf tmobile_cdf 2 > tmp.txt

gnuplot -p <<EOF
# scalable
#set terminal jpeg
#set output "$name.jpeg"
set terminal postscript eps color "Helvetica" 12
set size 0.5, 0.5
set output "$output.eps"
set autoscale
set xtic auto                          # set xtics automatically
set ytic auto                          # set ytics automatically
# set title 'CDF of $legend'
set xlabel "User Experienced Latency (s)"
set ylabel "CDF"

plot "tmp.txt" u 2:1 w lines lt 1 title "AT&T", \
     "" u 3:1 w lines lt 2 title "T-Mobile"
EOF
convert -density 300 "$output.eps" "$output.png"
rm -rf att_cdf tmobile_cdf tmp.txt 2> /dev/null
