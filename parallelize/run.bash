#!/bin/bash
for (( i=5; i<=1000; i++ ))
do  
  echo "Running at iteration "$i
  cd /home/anygroup/eval_909_32bit
  rm cache/static_graph_result_134548502_sweep_909_ziptest_exe9_32_10000
  python3 static_dep_graph.py >> s10000_18
  mv rr_inputs /home/anygroup/eval_909_32bit_rr_runs/rr_inputs
  cd /home/anygroup/eval_909_32bit_rr_runs
  ./run
  python3 combine.py
  python3 rename.py $i
  cp /home/anygroup/eval_909_32bit_rr_runs/rr_results.json /home/anygroup/eval_909_32bit/cache/rr_results_909_ziptest_exe9_32.json
done
