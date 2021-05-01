#!/bin/bash
dst= $HOME"/rr_runs/"
src=$PWD
folder=${PWD##*/}
mkdir $dst
cp -r $PWD $dst
cp $src"/parallelize/combine.py" $dst
cp $src"/parallelize/cp_script" $dst
cp $src"/parallelize/rename.py" $dst
cp $src"/parallelize/run" $dst
cp $src"/parallelize/run-rr.py" $dst$folder
cp $src"/parallelize/rr_util.py.record_rr_inputs" $src"/rr_util.py/"
cd $dst
./cp_script $folder
for (( i=1; i<=1000; i++ ))
do  
  echo "Running at iteration "$i
  cd $src#/home/anygroup/eval_909_32bit
  python3 static_dep_graph.py >> out
  mv rr_inputs $dst
  cd $dst
  ./run $folder
  python3 combine.py $folder $src $1
  python3 rename.py $i $folder
  cp $dst"rr_results.json" $src"/cache/rr_results"$1".json" #the program name
done
