set autoscale
set xtic auto                          # set xtics automatically
set ytic auto                          # set ytics automatically
set title 'Notification State change'
set xlabel "Time"
set ylabel "State"
set palette defined (2 "blue", 3 "red", 4 "green")
set cbrange [2:4]

plot "state_change.txt" using 1:2 with points  lt 4, \
    "state_change.txt" using 1:3 with points  lt 3, \
    "state_change.txt" using 1:4 with points  lt 2
