#!/bin/bash

file=$1
ylabel=$2
y_max=$3
y_min=$4
x_axis="Inter-packet time interval (s)"
key_pos="right"
gnuplot -p << EOF
set terminal postscript eps color "Arial" 22
set output "$file.eps"
set termoption dashed   # enable dashed line
set style line 1 lt 1 lc rgb "red" lw 2
set style line 2 lt 2 lc rgb "pink" lw 2
set style line 3 lt 3 lc rgb "orange" lw 2
set style line 4 lt 4 lc rgb "yellow" lw 2
set style line 5 lt 5 lc rgb "green" lw 2
set style line 6 lt 6 lc rgb "sea-green" lw 2
set style line 7 lt 7 lc rgb "cyan" lw 2
set style line 8 lt 8 lc rgb "blue" lw 2
set style line 9 lt 9 lc rgb "purple" lw 2
set style line 10 lt 10 lc rgb "brown" lw 2
set xrange[-0.5:16]
set yrange[$y_min:$y_max]
#set xtic rotate by -90
set key $key_pos
set xlabel "$x_axis"
set ylabel "$ylabel"
set xtic 0,1,15.5
set xtic font "Arial, 15"
#set boxwidth 0.15
#set style fill transparent solid 0.4
#set style fill transparent pattern 4 border
set style arrow 1 nohead lt 5 lw 1 lc rgb "black"
set label "DCH" at 1.25,4.5 center font "Arial, 18"
set label "FACH" at 4,4.5 center font "Arial, 18"
set label "PCH" at 6.75,4.5 center font "Arial, 18"

plot "$file.txt" using (\$1):(\$4):(\$4-\$5):(\$4+\$5) with errorbars title "Galaxy S3" lt 3 lc rgb "red" pt 9 ps 1.5, \
     "$file.txt" using (\$1):(\$4) with lines notitle lt 3 lw 2 lc rgb "red", \
     "$file.txt" using (\$1):(\$2) with lines notitle lt 1 lw 2 lc rgb "blue", \
     "$file.txt" using (\$1):(\$2):(\$2-\$3):(\$2+\$3) with errorbars title "HTC One S" lt 1 lc rgb "blue" pt 5 ps 1.5, \
     "dotedline.txt" using 1:(-1):(0):(\$2+1) with vectors arrowstyle 1 notitle
#plot "$file.txt" using (\$1):(\$4):(\$4-\$5):(\$4+\$5) with errorbars title "Device M1" lt 3 lc rgb "red" pt 9 ps 1.5, \
#     "$file.txt" using (\$1):(\$4) with lines notitle lt 3 lw 2 lc rgb "red", \
#     "$file.txt" using (\$1):(\$2) with lines notitle lt 1 lw 2 lc rgb "blue", \
#     "$file.txt" using (\$1):(\$2):(\$2-\$3):(\$2+\$3) with errorbars title "Device M2" lt 1 lc rgb "blue" pt 5 ps 1.5, \
#     "dotedline.txt" using 1:(-1):(0):(\$2+1) with vectors arrowstyle 1 notitle
EOF



