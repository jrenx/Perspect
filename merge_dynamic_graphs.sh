#!/bin/bash
SDIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
echo "Current dir is: "$SDIR
ips=()
while read -r line; do
    ips+=($line)
done < servers.config

for ip in "${ips[@]:1}"
do
    echo "Running cmd: scp "$ip":"$SDIR"/"$1"/dynamic_graph_result__*" ${ips[0]}":"$SDIR"/"$1
    scp $ip":"$SDIR"/"$1"/dynamic_graph_result__*" ${ips[0]}":"$SDIR"/"$1
done

for ip in "${ips[@]:1}"
do
    echo "Running cmd: scp "$SDIR"/"$1"/dynamic_graph_result__*" $ip":"$SDIR"/"$1
    scp ${ips[0]}":"$SDIR"/"$1"/dynamic_graph_result__*" $ip":"$SDIR"/"$1
done
