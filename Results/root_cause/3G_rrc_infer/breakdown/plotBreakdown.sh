#!/bin/bash

# plot the breakdown plot

input=$1
output=$2

../Tools/plot/historgramConverter.py 1 16 17 18 19 20 y < $input > tmp.txt

gnuplot -p <<EOF
set terminal postscript eps color "Helvetica" 26
set output "$output.eps"
set size 1.4, 1
set style data histogram
set style histogram rowstack gap 2
set style fill solid 1.00
set boxwidth 0.6
set xtics font "Helvetica, 20"
set xtics rotate by -45
set xlabel "Inter-packet interval (s)"
set ylabel "Breakdown UDP RTT (s)"

plot newhistogram "", \
     "tmp.txt" using 2:xtic(1) fs pattern 3 lw 6 lt 1 lc rgb "red" title "DCH_to_FACH demotion", \
     "" using 3 fs pattern 8 lw 3 lt 1 lc rgb "purple" title "FACH_to_PCH demotion", \
     "" using 4 fs pattern 4 lw 6 lt 1 lc rgb "green" title "PCH_to_FACH promotion", \
     "" using 5 fs pattern 1 lw 3 lt 1 lc rgb "orange" title "FACH_to_DCH promotion", \
     "" using 6 fs pattern 5 lw 6 lt 1 lc rgb "blue" title "Remaining delay"

EOF
convert -density 300 "$output.eps" "$output.png"
#rm -rf tmp.txt 2> /dev/null
