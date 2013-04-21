#!/bin/bash
echo "Please sudo su first"
echo "--- Before Free Up Memory ---"
free -m
sync
echo 3 > /proc/sys/vm/drop_caches
echo "--- After Free Up Memory ---"
free -m
