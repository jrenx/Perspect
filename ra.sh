#!/bin/bash
if [ ! -z $3 ] 
then
  ./copy_all.sh $3 $4
fi
./spawn_all.sh "python3.7 ra-worker.py" "ra_worker.log"${2:-}
echo "Waiting "$1" seconds for the workers to become ready"
sleep $1
python3.7 ra-client.py &> "ra_client.log"${2:-}
