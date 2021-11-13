#!/bin/bash
echo "usage example: ./spawn_all.sh  "'"'"python3.7 ra-worker.py"'"'" "'"'"ra_worker.log"'"'
SDIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
echo "Current dir is: "$SDIR
echo "Command: "$1" Argument: "$2
ips=()
while read -r line; do
    ips+=($line)
done < servers.config

for ip in "${ips[@]}"
do
    echo "Starting on "$ip
    cmd="cd "$SDIR"; nohup "$1" > "$2" 2>&1 &"
    echo $cmd
    ssh $ip $cmd
done
