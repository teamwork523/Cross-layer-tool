#!/bin/bash

# plot the breakdown plot

input=$1
output=$2

../Tools/plot/historgramConverter.py 1 16 17 18 19 20 21 y < $input > tmp.txt

gnuplot -p <<EOF
set terminal postscript eps color "Helvetica" 24
set key spacing 0.95
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
     "tmp.txt" using 2:xtic(1) fs pattern 3 lw 4 lt 1 lc rgb "red" title "DCH->FACH process delay", \
     "" using 3 fs pattern 8 lw 3 lt 1 lc rgb "pink" title "FACH->PCH process delay", \
     "" using 4 fs pattern 4 lw 4 lt 1 lc rgb "green" title "PCH->FACH process delay", \
     "" using 5 fs pattern 1 lw 3 lt 1 lc rgb "orange" title "FACH->DCH process delay", \
     "" using 7 fs pattern 6 lw 4 lt 1 lc rgb "purple" title "Configuration and measurement delay", \
     "" using 6 fs pattern 5 lw 4 lt 1 lc rgb "cyan" title "Network delay"
     

EOF
convert -density 300 "$output.eps" "$output.png"
#rm -rf tmp.txt 2> /dev/null
