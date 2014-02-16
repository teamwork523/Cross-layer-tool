#!/bin/bash

att_file=$1
tmobile_file=$2
output=$3
legend=$4
# Generate CDF plot
# plot Promotion timer
#../Tools/plot/cdfConverterWithFilter.py 2 1 n 1 DCH_to_Disconnect < $att_file > att_cdf

# plot PCH_to_FACH and FACH_to_DCH for tmobile
../Tools/plot/cdfConverterWithFilter.py 2 1 n 1 Connected_to_Idle_Camped < $tmobile_file > tmobile_cdf

# merge two cdf file
#../Tools/common/mergeTwoFile.py att_cdf tmobile_cdf 2 3 > tmp.txt

gnuplot -p <<EOF
# scalable
#set terminal jpeg
#set output "$name.jpeg"
set terminal postscript eps color "Helvetica" 12
set size 0.5, 0.5
set output "$output.eps"
set autoscale
set key font ", 9"
#set key spacing 0.7
set key bottom
set xtics auto                       # set xtics automatically
#set logscale x 2
set ytic auto                          # set ytics automatically
# set title 'CDF of $legend'
set xlabel "Demotion timer in QxDM (s)"
#set xlabel "AT&T Disconnected_to_DCH without Fast Dormancy"
set ylabel "CDF"
#     "" u 4:1 w lines lt 2 title "AT&T Multiple FACH_to_DCH"

#plot "tmp.txt" u 2:1 w lines lt 8 lc rgb "orange" title "AT&T Normal",
#     "" u 3:1 w lines lt 1 title "AT&T FACH_to_DCH", 
#     "" u 4:1 w lines lt 9 lc rgb "green" title "T-Mobile Normal",
#     "" u 5:1 w lines lt 7 title "T-Mobile FACH_to_DCH",
#     "" u 6:1 w lines lt 5 title "T-Mobile PCH_to_DCH",
#     "" u 7:1 w lines lt 11 lc rgb "pink" title "T-Mobile Inaccurate RRC state"

plot "tmobile_cdf" u 2:1 w linespoints lt 8 pi -30 ps 1 pt 3 lc rgb "orange" title "T-Mobile connected to idle_camped"
#     "" u 3:1 w linespoints lt 1 pi -30 ps 1 pt 2 title "T-Mobile FACH_to_PCH",
#     "" u 4:1 w linespoints lt 9 pi -30 ps 1 pt 5 lc rgb "green" title "T-Mobile DCH_to_FACH"

EOF
convert -density 300 "$output.eps" "$output.png"
rm -rf att_cdf tmobile_cdf tmp.txt 2> /dev/null
