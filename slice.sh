#!/bin/bash
./spawn_all.sh "python3.7 parallelize-worker.py" "worker.log"
sleep $1
python3.7 parallelize-client.py &> client.log
