#!/bin/bash

data_col=$1
att_file=$2
tmobile_file=$3
output=$4
anonymous=$5
# Generate CDF plot
# plot Normal, PCH_to_DCH, mulitple FACH_to_DCH and FACH_to_DCH for tmobile
../Tools/plot/cdfConverterWithFilter.py $data_col 1 n 2 Normal DCH_TO_FACH FACH_TO_DCH PCH_TO_FACH+FACH_TO_DCH < $tmobile_file > tmobile_cdf

# plot Normal, mulitple FACH_to_DCH and FACH_to_DCH for att
../Tools/plot/cdfConverterWithFilter.py $data_col 1 n 2 Normal DCH_TO_DISCONNECTED DISCONNECTED_TO_DCH < $att_file > att_cdf

att_name="AT&T"
tmobile_name="T-Mobile"
if [ $anonymous = "y" ]; then
    att_name="C2"
    tmobile_name="C1"
fi

point_size=2

gnuplot -p <<EOF

set terminal postscript eps color "Helvetica" 22
set output "$output.eps"

set multiplot layout 2,1
set key font ", 17"
set key spacing 0.8
set key bottom
set xtics 1                          # set xtics automatically
set ytic 0.2                          # set ytics automatically
# set title 'CDF of $legend'
set ylabel "CDF"

plot "tmobile_cdf" u 2:1 w linespoints lt 4 pi -15 ps $point_size pt 4 lc rgb "red" title "$tmobile_name DCH", \
     "" u 4:1 w linespoints lt 1 pi -15 ps $point_size pt 6 lc rgb "blue" title "$tmobile_name FACH->DCH", \
     "" u 3:1 w linespoints lt 3 pi -15 ps $point_size pt 8 lc rgb "green" title "$tmobile_name DCH->FACH->DCH", \
     "" u 5:1 w linespoints lt 5 pi -15 ps $point_size pt 3 lc rgb "cyan" title "$tmobile_name PCH->FACH->DCH"

set xlabel "User experienced latency (s)"

plot "att_cdf" u 2:1 w linespoints lt 4 pi -15 ps $point_size pt 4 lc rgb "red" title "$att_name DCH", \
     "" u 4:1 w linespoints lt 1 pi -15 ps $point_size pt 6 lc rgb "blue" title "$att_name Disconnected->DCH", \
     "" u 3:1 w linespoints lt 3 pi -15 ps $point_size pt 8 lc rgb "green" title "$att_name DCH->Disconnected->DCH"
     
unset multiplot

EOF
convert -density 300 "$output.eps" "$output.png"
rm -rf att_cdf tmobile_cdf 2> /dev/null
