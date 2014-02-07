#!/bin/bash

file=$1
output=$file
#y_max=$3
#y_min=$4
key_pos="right"
xtic_font_size=14
#if (( $raw_num == 3 ));then
#    x_axis="UDP Loss Root Causes"
#    key_pos="left"
#    xtic_font_size=18
#fi
# process data
Tools/data/boxErrorBarWithThreeDim.py 1 3 2 n < $file > tmp.txt
raw_num=$(wc -l tmp.txt | cut -d" " -f1)
gnuplot -p << EOF
set terminal postscript eps color "Helvetica" 21
set output "$output.eps"
set termoption dashed   # enable dashed line
set xrange[0:$raw_num]
#set yrange[$y_min:$y_max]
set xtic rotate by -25
set key $key_pos
set key font ", 16"
#set xlabel "URLs"
set ylabel "User Experienced Latency (s)"
set xtic offset 0.5 font "Helvetica, $xtic_font_size"
set boxwidth 0.15
#set style fill transparent solid 0.4
set style fill transparent pattern 4 border 

plot "tmp.txt" using (\$2-.1):3:4:5:(0.15):xtic(1) with boxerrorbars lc 1 lw 2 title "Normal Requests", \
     "" using (\$2+0.05):6:7:8:(0.15) with boxerrorbars lc 3 lw 2 title "FACH_to_DCH Interferred Requests", \
     "" using (\$2+0.2):9:10:11:(0.15) with boxerrorbars lc 2 lw 2 title "PCH_to_DCH Interferred Requests", \
     "" using (\$2+0.35):12:13:14:(0.15) with boxerrorbars lc 4 lw 2 title "Inaccurate RRC state Requests"


EOF
convert -density 300 "$output.eps" "$output.png"
rm -rf tmp.txt 2> /dev/null
