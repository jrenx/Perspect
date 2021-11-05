#!/bin/bash
ips=()
while read -r line; do
    ips+=($line)
done < servers.config

for ip in "${ips[@]}"
do
    echo "Removing on "$ip
    ssh $ip rm "/home/renxian2/eval_mongodb_44991/"$1
done
