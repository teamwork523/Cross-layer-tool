#!/bin/bash

file=$1
output=$file
# Generate all the necessary tmp file
../Tools/plot/http_detail_trace_generator.py < $file
#tit=$2
gnuplot -p << EOF
set terminal postscript eps color "Arial" 18
set output "$output.eps"
set termoption dashed   # enable dashed line

set multiplot layout 2,1   # plot comparison
# Upper layer
set xrange [-3.5:9]
set yrange [0:6]
set key nobox 
set key width -2
set key samplen 4
set key font ",16"
#set key in vert
set key right bottom                         # move the legend outside
set xlabel "Time (s)"
#set ylabel "IP Packets"
#set grid

#set style arrow 2 nohead lt 6 lw 1
set style line 4 lt 1 lc rgb "red" lw 2
# customize label
set ytics("PCH" 1, "PCH/FACH Transition" 2, "FACH" 3, "FACH/DCH Transition" 4, "DCH" 5)
plot "tmp_IP.txt" using 1:2 with linespoints linestyle 4 title "IP packets"

# lower layer
set xrange [-3.5:9]
set yrange [0:6]
set key nobox
set key width -2
set key samplen 4
set key font ",16"
set key right bottom                         # move the legend outside
set xlabel "Time (s)"
#set ylabel "RRC state transition"
set style arrow 1 head lt 2 lc rgb "blue" lw 2 
set style arrow 3 head lt 5 lc rgb "#FC0FC0" lw 2 # pink
set style arrow 4 head lt 6 lc rgb "green" lw 2
set style arrow 5 head lt 7 lc rgb "orange" lw 2
#set style line 2 lt 1 lc rgb "green" lw 8
#set style line 3 lt 2 lc rgb "cyan" lw 8
#  "tmp_RLC_begin.txt" using 1:(0):(0):2 with vectors arrowstyle 1 title "RLC Mapped First PDU"
#     "tmp_RLC_end.txt" using 1:(0):(0):2 with vectors arrowstyle 3 title "RLC Mapped Last PDU"
#     "tmp_DCH_to_FACH_start.txt" using 1:(4) with points pt 3 lc rgb 'green' title "DCH_to_FACH Begin", 
#     "tmp_DCH_to_FACH_end.txt" using 1:(2) with points pt 4 lc rgb 'orange' title "DCH_to_FACH End", 
#      "tmp_PCH_to_FACH_end.txt" using 1:(2) with points pt 8 lc rgb 'purple' title "PCH_to_FACH End"
#      "tmp_FACH_to_PCH_start.txt" using 1:(2) with points pt 5 lc rgb 'sea-green' title "FACH_to_PCH Begin"
#      "tmp_FACH_to_PCH_end.txt" using 1:(2) with points pt 6 lc rgb 'yellow' title "FACH_to_PCH End"
#      "tmp_PCH_to_FACH_start.txt" using 1:(2) with points pt 7 lc rgb 'cyan' title "PCH_to_FACH Begin"

plot  "tmp_FACH_to_DCH_start.txt" using 1:2 with points pt 1 lc rgb 'blue' title "FACH_to_DCH Begin", \
      "tmp_FACH_to_DCH_end.txt" using 1:2 with points pt 2 lc rgb 'red' title "FACH_to_DCH End"


unset multiplot
EOF
convert -density 300 "$output.eps" "$output.png"
rm -rf tmp_*.txt 2> /dev/null
