#!/bin/bash

file=$1
x_type=$2
output=$3
y_col=$4
xlabel="RRC states and RRC state transitions"
ylabel=""
key_pos="right"
xtic_font_size=14

if [ $y_col -eq 2 ]; then
    ylabel="TCP RTT (s)"
    output="${output}_tcp_rtt"
elif [ $y_col -eq 4 ]; then
    ylabel="RLC Normalized Transmission Delay (ms)"
    output="${output}_norm_trans_delay"
fi

if [[ $x_type == "reset" ]];then
    Tools/data/boxErrorBarWithCond.py 1 $y_col 10 ">0" y < $file > tmp.txt
    trueLegend="PRACH reset events exist"
    falseLegend="No PRACH reset events exist"
elif [[ $x_type == "done" ]];then
    Tools/data/boxErrorBarWithCond.py 1 $y_col 11 ">0" y < $file > tmp.txt
    trueLegend="PRACH done events exist"
    falseLegend="No PRACH done events exist"
fi
raw_num=$(wc -l tmp.txt | cut -d" " -f1)

gnuplot -p << EOF
set terminal postscript eps color "Arial" 21
set output "$output.eps"
set termoption dashed   # enable dashed line
set xrange[0:$raw_num]
#set yrange[$y_min:$y_max]
set xtic rotate by -25
set key $key_pos
set xlabel "$xlabel"
set ylabel "$ylabel"
set xtic offset 0.5 font "Arial, $xtic_font_size"
set boxwidth 0.25
#set style fill transparent solid 0.4
set style fill transparent pattern 4 border

plot "tmp.txt" using (\$2-.05):3:4:5:(0.25):xtic(1) with boxerrorbars lc 1 lw 4 title "$trueLegend", \
     "" using (\$2+0.25):6:7:8:(0.25) with boxerrorbars lc 3 lw 4 title "$falseLegend"
EOF
convert -density 300 "$output.eps" "$output.png"
rm tmp.txt 2> /dev/null
