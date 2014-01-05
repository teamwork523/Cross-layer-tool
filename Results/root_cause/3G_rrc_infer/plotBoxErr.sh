#!/bin/bash

file=$1
x_type=$2
output=$3
x_label="PRACH message type"
ylabel="RLC Normalized Transmission Delay (ms)"
key_pos="right"
xtic_font_size=14

if [[ $x_type == "reset" ]];then
    Tools/data/boxErrorBarWithCondSingle.py 3 9 ">0" PRACH_Reset y < $file > tmp.txt
elif [[ $x_type == "done" ]];then
    Tools/data/boxErrorBarWithCondSingle.py 3 10 ">0" PRACH_Done y < $file > tmp.txt
fi
raw_num=$(wc -l tmp.txt | cut -d" " -f1)

gnuplot -p << EOF
set terminal postscript eps color "Arial" 21
set output "$output.eps"
set termoption dashed   # enable dashed line
set xrange[0:$raw_num]
# set xtic rotate by -25
set key $key_pos
set xlabel "$xlabel"
set ylabel "$ylabel"
set xtic offset 0.5 font "Arial, $xtic_font_size"
set boxwidth 0.25
#set style fill transparent solid 0.4
set style fill transparent pattern 4 border

plot "tmp.txt" using 2:3:4:5:(0.15):xtic(1) with boxerrorbars lc 1 lw 4 title "Uplink"
EOF
convert -density 300 "$output.eps" "$output.png"
rm tmp.txt 2> /dev/null
