#!/bin/bash

for i in 3.5 4 4.5 5 ; do
    ../../../tool/cdfConverter.py 1 1 n < uplink_$i > uplink_gap_$i\_cdf        
done
