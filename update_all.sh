#!/bin/bash
SDIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
echo "Current dir is: "$SDIR
git push
ips=()
while read -r line; do
    ips+=($line)
done < servers.config

for ip in "${ips[@]}"
do
    echo "Updating "$ip
    ssh $ip $SDIR"/"update.sh
done
