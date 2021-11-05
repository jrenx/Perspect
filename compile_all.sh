#!/bin/bash
ips=()
while read -r line; do
    ips+=($line)
done < servers.config

for ip in "${ips[@]}"
do
    echo "Updating "$ip
    ssh $ip /home/renxian2/eval_mongodb_44991/compile.sh
done
