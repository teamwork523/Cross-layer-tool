#!/bin/bash

file=$1
output=$file
#y_max=$3
#y_min=$4
raw_num=$(wc -l $file | cut -d" " -f1)
key_pos="right"
xtic_font_size=14
#if (( $raw_num == 3 ));then
#    x_axis="UDP Loss Root Causes"
#    key_pos="left"
#    xtic_font_size=18
#fi
gnuplot -p << EOF
set terminal postscript eps color "Arial" 21
set output "$output.eps"
set termoption dashed   # enable dashed line
set xrange[0:$raw_num]
#set yrange[$y_min:$y_max]
set xtic rotate by -25
set key $key_pos
#set xlabel "URLs"
set ylabel "User Experienced Latency (s)"
set xtic offset 0.5 font "Arial, $xtic_font_size"
set boxwidth 0.25
#set style fill transparent solid 0.4
set style fill transparent pattern 4 border

plot "$file" using (\$2-.05):3:4:5:(0.3):xtic(1) with boxerrorbars lc 1 lw 4 title "Interfered URLs", \
     "" using (\$2+0.25):6:7:8:(0.3) with boxerrorbars lc 3 lw 4 title "Normal URLs"
EOF
convert -density 300 "$output.eps" "$output.png"
