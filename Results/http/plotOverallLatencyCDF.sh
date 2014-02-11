#!/bin/bash

data_col=$1
att_file=$2
tmobile_file=$3
output=$4
# Generate CDF plot
# plot Normal, mulitple FACH_to_DCH and FACH_to_DCH for att
Tools/plot/cdfConverterWithFilter.py $data_col 1 n 2 Normal DCH < $att_file > att_cdf

# plot Normal, PCH_to_DCH, mulitple FACH_to_DCH and FACH_to_DCH for tmobile
Tools/plot/cdfConverterWithFilter.py $data_col 1 n 2 Normal DCH FACH+DCH < $tmobile_file > tmobile_cdf

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
set key font ", 10"
#set key spacing 0.7
set key bottom
set xtics 1                          # set xtics automatically
set ytic auto                          # set ytics automatically
# set title 'CDF of $legend'
set xlabel "User experienced latency (s)"
set ylabel "CDF"
#     "" u 4:1 w lines lt 2 title "AT&T multiple FACH_to_DCH"

#plot "tmp.txt" u 2:1 w lines lt 8 lc rgb "orange" title "AT&T Normal",
#     "" u 3:1 w lines lt 1 title "AT&T FACH_to_DCH", 
#     "" u 4:1 w lines lt 9 lc rgb "green" title "T-Mobile Normal",
#     "" u 5:1 w lines lt 7 title "T-Mobile FACH_to_DCH",
#     "" u 6:1 w lines lt 5 title "T-Mobile PCH_to_DCH",
#     "" u 7:1 w lines lt 11 lc rgb "pink" title "T-Mobile Inaccurate RRC state"

plot "tmp.txt" u 2:1 w linespoints lt 8 pi -15 ps 1 pt 3 lc rgb "orange" title "AT&T normal", \
     "" u 3:1 w linespoints lt 1 pi -15 ps 1 pt 2 title "AT&T Disconnected_to_DCH", \
     "" u 4:1 w linespoints lt 9 pi -15 ps 1 pt 5 lc rgb "green" title "T-Mobile normal", \
     "" u 5:1 w linespoints lt 8 pi -15 ps 1 pt 8 lc rgb "black" title "T-Mobile FACH_to_DCH", \
     "" u 6:1 w linespoints lt 5 pi -15 ps 1 pt 7 title "T-Mobile PCH_to_DCH"

EOF
convert -density 300 "$output.eps" "$output.png"
rm -rf att_cdf tmobile_cdf tmp.txt 2> /dev/null
