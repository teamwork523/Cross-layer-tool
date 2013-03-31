#!/bin/bash

gnuplot -p << EOF
set term pngcairo dashed
set output "foo.png"
test
!display foo.png
!rm foo.png
EOF
