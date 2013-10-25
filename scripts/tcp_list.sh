#!/bin/bash

for i in $(ls /proc/sys/net/ipv4/tcp_*);do ls $i; cat $i; done
