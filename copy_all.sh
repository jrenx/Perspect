#!/bin/bash
ips=()
while read -r line; do
    ips+=($line)
done < servers.config

for ip in "${ips[@]}"
do
    echo "Copying to "$ip
    scp $1$2 $ip":"$1
done
