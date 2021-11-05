#!/bin/bash
SDIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
echo "WARN: you need to comment out the code section under '# If not running interactively, don't do anything' in beginning of ~/.bashrc in order for this script to work."
echo "Current dir is: "$SDIR
ips=()
while read -r line; do
    ips+=($line)
done < servers.config

for ip in "${ips[@]}"
do
    echo "Updating "$ip
    ssh $ip $SDIR"/"compile.sh
done
