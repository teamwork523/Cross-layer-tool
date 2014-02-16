#!/bin/bash

att_file=$1
tmobile_file=$2
output=$3
# Generate CDF plot
TOOL_PATH="../../Tools/"
# plot Promotion timer
$TOOL_PATH/plot/cdfConverterWithFilter.py 2 1 n 1 connect_setup < $att_file > att_cdf

# plot PCH_to_FACH and FACH_to_DCH for tmobile
$TOOL_PATH/plot/cdfConverterWithFilter.py 2 1 n 1 PCH_to_FACH FACH_to_DCH < $tmobile_file > tmobile_cdf

# merge two cdf file
$TOOL_PATH/common/mergeTwoFile.py att_cdf tmobile_cdf 2 3 > tmp.txt

gnuplot -p <<EOF
# scalable
#set terminal jpeg
#set output "$name.jpeg"
set terminal postscript eps color "Helvetica" 12
set size 0.5, 0.5
set output "$output.eps"
set autoscale
#set key font ", 6"
#set key spacing 0.7
set key bottom
#set xtics                          # set xtics automatically
set logscale x 10
set ytic auto                          # set ytics automatically
# set title 'CDF of $legend'
set xlabel "Promotion process delay in QxDM (s)"
set ylabel "CDF"
#     "" u 4:1 w lines lt 2 title "AT&T Multiple FACH_to_DCH"

#plot "tmp.txt" u 2:1 w lines lt 8 lc rgb "orange" title "AT&T Normal",
#     "" u 3:1 w lines lt 1 title "AT&T FACH_to_DCH", 
#     "" u 4:1 w lines lt 9 lc rgb "green" title "T-Mobile Normal",
#     "" u 5:1 w lines lt 7 title "T-Mobile FACH_to_DCH",
#     "" u 6:1 w lines lt 5 title "T-Mobile PCH_to_DCH",
#     "" u 7:1 w lines lt 11 lc rgb "pink" title "T-Mobile Inaccurate RRC state"

plot "tmp.txt" u 2:1 w linespoints lt 8 pi -30 ps 1 pt 3 lc rgb "orange" title "AT&T connection setup", \
     "" u 3:1 w linespoints lt 1 pi -30 ps 1 pt 2 title "T-Mobile PCH_to_FACH", \
     "" u 4:1 w linespoints lt 9 pi -30 ps 1 pt 5 lc rgb "green" title "T-Mobile FACH_to_DCH"

EOF
convert -density 300 "$output.eps" "$output.png"
rm -rf att_cdf tmobile_cdf tmp.txt 2> /dev/null
