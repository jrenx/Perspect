#!/bin/bash
SDIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
if [ ! -z $3 ] 
then
  ./copy_all.sh $3 $4
fi
./spawn_all.sh "python3.7 ra-worker.py" "ra_worker.log"${2:-}
echo "Waiting "$1" seconds for the workers to become ready"
sleep $1

ips=()
while read -r line; do
    ips+=($line)
done < servers.config

for ip in "${ips[@]}"
do
	echo "Waiting for the worker to be ready on "$ip
	while [ 1 ]
	do
		if ssh $ip "stat "$SDIR"/ra_worker_ready" \> /dev/null 2\>\&1
		then
			break
		fi
	done
done
python3.7 ra-client.py &> "ra_client.log"${2:-}
