#!/bin/bash
for ip in 10.1.0.17 10.1.0.18 10.1.0.19 10.1.0.20 10.1.0.21 10.1.0.22 10.1.0.23 10.1.0.24
do
    echo "Updating "$ip
    ssh $ip /home/renxian2/eval_mongodb_44991/update.sh
done


