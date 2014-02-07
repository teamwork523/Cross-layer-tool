#!/bin/bash

data_col=$1
att_file=$2
tmobile_file=$3
output=$4
# Generate CDF plot
# plot mulitple FACH_to_DCH and FACH_to_DCH for att
Tools/plot/cdfConverterWithFilter.py $data_col 1 n 2 DCH < $att_file > att_cdf

# plot PCH_to_DCH, mulitple FACH_to_DCH and FACH_to_DCH for tmobile
Tools/plot/cdfConverterWithFilter.py $data_col 1 n 2 DCH FACH+DCH Inaccurate < $tmobile_file > tmobile_cdf

# merge two cdf file
Tools/common/mergeTwoFile.py att_cdf tmobile_cdf 2 3 4 > tmp.txt

gnuplot -p <<EOF
# scalable
#set terminal jpeg
#set output "$name.jpeg"
set terminal postscript eps color "Helvetica" 12
set size 0.5, 0.5
set output "$output.eps"
set autoscale
set key font ", 8"
set key spacing 0.7
set key right bottom
set mxtics 32
set logscale x 10
set xtics (0.1,0.2,0.5,1,2,5,10)
set ytic auto                          # set ytics automatically
# set title 'CDF of $legend'
set xlabel "Inflated Inter-packet Latency in log-scale (s)"
set ylabel "CDF"
#      "" u 3:1 w lines lt 2 title "AT&T Multiple FACH_to_DCH"

plot "tmp.txt" u 2:1 w linespoints lt 1 pi -15 ps 1 pt 2 title "AT&T FACH_to_DCH", \
     "" u 3:1 w linespoints lt 7 pi -15 ps 1 pt 4 title "T-Mobile FACH_to_DCH", \
     "" u 4:1 w linespoints lt 5 pi -15 ps 1 pt 6 title "T-Mobile PCH_to_DCH", \
     "" u 5:1 w linespoints lt 11 pi -15 ps 1 lc rgb "pink" pt 8 title "T-Mobile Inaccurate RRC state"
EOF
convert -density 300 "$output.eps" "$output.png"
rm -rf att_cdf tmobile_cdf tmp.txt 2> /dev/null
