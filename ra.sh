#!/bin/bash
./spawn_all.sh "python3.7 ra-worker.py" "ra_worker.log"
echo "Waiting "$1" seconds for the workers to become ready"
sleep $1
python3.7 ra-client.py &> ra_client.log
