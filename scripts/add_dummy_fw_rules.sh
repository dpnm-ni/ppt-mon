#!/bin/bash
#
# create dummy iptables rules that packet need to travel all of them
#

dummy_subnet="10.2"
from=200
to=250

for m in $(seq $from $to); do
    for i in $(seq 150 200); do
        sudo iptables -A FORWARD -s $dummy_subnet.$m.$i -p tcp --dport $m -j DROP
        sudo iptables -A INPUT -s $dummy_subnet.$m.$i -p tcp --dport $m -j DROP
    done
done
