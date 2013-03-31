set xdata time
set timefmt "%s"
set format x "%H:%M"     # or anything else
set autoscale
set xtic auto                          # set xtics automatically
set ytic auto                          # set ytics automatically
set title 'Power Result from QCAT'
set xlabel "Time"
set ylabel "Transmission Power (mW)"

plot "power.txt" using 1:3 with lines lt 5 lw 2 title columnheader
