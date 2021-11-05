#!/bin/bash
./spawn_all.sh "python3.7 parallelize-worker.py" "worker.log"
echo "Waiting "$1" seconds for the workers to become ready"
sleep $1
python3.7 parallelize-client.py &> client.log
