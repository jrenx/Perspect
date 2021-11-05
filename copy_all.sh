#!/bin/bash
SDIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
echo "Current dir is: "$SDIR
ips=()
while read -r line; do
    ips+=($line)
done < servers.config

for ip in "${ips[@]}"
do
    echo "Copying to "$ip
    scp $SDIR"/"$1 $ip":"$2
done
