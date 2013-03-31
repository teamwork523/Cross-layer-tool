set xdata time
set timefmt "%s"
set format x "%H:%M"     # or anything else
set autoscale
set xtic auto                          # set xtics automatically
set ytic auto                          # set ytics automatically
set title 'Raw bit Rate Result from QCAT'
set xlabel "Time"
set ylabel "Raw bit rate (kbps)"

plot "speed.txt" using 1:2 with lines lt 4 lw 2 title columnheader
