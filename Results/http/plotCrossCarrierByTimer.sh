#!/bin/bash

data_col=$1
att_file=$2
tmobile_file=$3
output=$4
# Generate Box Plot
./groupByTimer.py 4 $data_col n < $att_file > att_cdf
./groupByTimer.py 4 $data_col n < $tmobile_file > tmobile_cdf
Tools/common/mergeTwoFile.py att_cdf tmobile_cdf 3 4 5 > tmp.txt

raw_num=$(wc -l tmp.txt | cut -d" " -f1)
gnuplot -p << EOF
set terminal postscript eps color "Helvetica" 21
set output "$output.eps"
set termoption dashed   # enable dashed line
set xrange[0:$raw_num]
#set yrange[$y_min:$y_max]
#set xtic rotate by -25
set key $key_pos
set key font ", 16"
set ylabel "User Experienced Latency (s)"
set xlabel "Inter-request Time (s)"
set xtic offset 0.5 font "Helvetica, $xtic_font_size"
set boxwidth 0.15
#set style fill transparent solid 0.4
set style fill transparent pattern 4 border

plot "tmp.txt" using (\$2-.1):3:4:5:(0.25):xtic(1) with boxerrorbars lc 1 lw 2 title "AT&T", \
     "" using (\$2+0.15):6:7:8:(0.25) with boxerrorbars lc 3 lw 2 title "T-Mobile"
EOF
convert -density 300 "$output.eps" "$output.png"
rm -rf att_cdf tmobile_cdf tmp.txt 2> /dev/null
