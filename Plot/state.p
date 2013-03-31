set xdata time
set timefmt "%s"
set format x "%H:%M"     # or anything else
set autoscale
set xtic auto                          # set xtics automatically
set ytic auto                          # set ytics automatically
set title 'State plot'
set xlabel "Time"
set ylabel "State (FACH = 2, DCH = 3, PCH = 4)"
set palette defined (2 "blue", 3 "red", 4 "green")
set cbrange [2:4]

plot "state.txt" using 1:2 with point  lt 5 lw 5
