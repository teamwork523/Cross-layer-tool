#!/bin/bash

file=$1
ylabel=$2
y_max=$3
y_min=$4
raw_num=$(wc -l $file.txt | cut -d" " -f1)
x_axis="RRC States"
key_pos="right"
xtic_font_size=14
if (( $raw_num == 3 ));then
    x_axis="UDP Loss Root Causes"
    key_pos="left"
    xtic_font_size=18
fi
gnuplot -p << EOF
set terminal postscript eps color "Arial" 21
set output "$file.eps"
set termoption dashed   # enable dashed line
set xrange[0:$raw_num]
set yrange[$y_min:$y_max]
#set xtic rotate by -25
set key $key_pos
set xlabel "$x_axis"
set ylabel "$ylabel"
set xtic offset 0.5 font "Arial, $xtic_font_size"
set boxwidth 0.25
#set style fill transparent solid 0.4
set style fill transparent pattern 4 border

plot "$file.txt" using (\$2-.05):5:6:xtic(1) with boxerrorbars lc 1 lw 4 title "Galaxy S3", \
     "" using (\$2+0.25):3:4 with boxerrorbars lc 3 lw 4 title "HTC One S"
#plot "$file.txt" using (\$2-.05):5:6:xtic(1) with boxerrorbars lc 1 lw 4 title "Device M1", \
#     "" using (\$2+0.25):3:4 with boxerrorbars lc 3 lw 4 title "Device M2"
EOF
