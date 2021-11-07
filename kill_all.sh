#!/bin/bash
SDIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
echo "Current dir is: "$SDIR
ips=()
while read -r line; do
    ips+=($line)
done < servers.config

for ip in "${ips[@]}"
do
    echo "Cleaning up jobs on "$ip
    ssh $ip $SDIR"/"kill.sh
done


