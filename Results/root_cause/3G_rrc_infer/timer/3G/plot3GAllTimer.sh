#!/bin/bash

att_file=$1
tmobile_file=$2
output=$3
point_size=1.5
# Generate CDF plot
TOOL_PATH="../../Tools/"
# plot AT&T Demotion timer
$TOOL_PATH/plot/cdfConverterWithFilter.py 2 1 n 1 DCH_to_Disconnect < $att_file > att_cdf

# plot T-Mobile Demotion timer
$TOOL_PATH/plot/cdfConverterWithFilter.py 2 1 n 1 FACH_to_PCH_with_phy_reconfig DCH_to_FACH < $tmobile_file > tmobile_cdf

# merge two demote files
$TOOL_PATH/common/mergeTwoFile.py att_cdf tmobile_cdf 2 3 > tmp_demote.txt

# plot AT&T Demotion timer
$TOOL_PATH/plot/cdfConverterWithFilter.py 2 1 n 1 connect_setup < $att_file > att_cdf

# plot T-Mobile Demotion timer
$TOOL_PATH/plot/cdfConverterWithFilter.py 2 1 n 1 PCH_to_FACH FACH_to_DCH < $tmobile_file > tmobile_cdf

# merge two promote files
$TOOL_PATH/common/mergeTwoFile.py att_cdf tmobile_cdf 2 3 > tmp_promote.txt

gnuplot -p <<EOF
set terminal postscript eps color "Helvetica" 18
#set size 0.5, 0.5
set output "$output.eps"

# Plot multiple graph
set multiplot layout 2,1
# Plot promotion
set key bottom
set logscale x 10
set ytic 0.2                          # set ytics automatically
set xlabel "Promotion process delay from QxDM in logscale (s)"
set ylabel "CDF"
plot "tmp_promote.txt" u 2:1 w linespoints lt 8 pi -30 ps $point_size pt 3 lc rgb "orange" title "AT&T connection setup", \
     "" u 3:1 w linespoints lt 1 pi -30 ps $point_size pt 2 title "T-Mobile PCH_to_FACH", \
     "" u 4:1 w linespoints lt 9 pi -30 ps $point_size pt 5 lc rgb "green" title "T-Mobile FACH_to_DCH"
unset logscale x

# Plot demotion
#set key font ", 9"
set key bottom
set xtics auto                       # set xtics automatically
set ytic 0.2                          # set ytics automatically
set xlabel "Demotion timer from QxDM (s)"
set ylabel "CDF"

plot "tmp_demote.txt" u 2:1 w linespoints lt 8 pi -30 ps $point_size pt 3 lc rgb "orange" title "AT&T DCH_to_disconnected",\
     "" u 3:1 w linespoints lt 1 pi -30 ps $point_size pt 2 title "T-Mobile FACH_to_PCH",\
     "" u 4:1 w linespoints lt 9 pi -30 ps $point_size pt 5 lc rgb "green" title "T-Mobile DCH_to_FACH"

unset multiplot

EOF
convert -density 300 "$output.eps" "$output.png"
rm -rf att_cdf tmobile_cdf tmp.txt 2> /dev/null
