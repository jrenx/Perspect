#!/bin/bash
src=$PWD
folder=${PWD##*/}
dst=$HOME"/"$folder"_rr_runs/"
echo "source: "$src
echo "destination: "$dst
mkdir $dst
cp $src"/parallelize/rr_util.py.record_rr_inputs" $src"/rr_util.py"
cp -r $PWD $dst
cp $src"/parallelize/combine.py" $dst
cp $src"/parallelize/cp_script" $dst
cp $src"/parallelize/rename.py" $dst
cp $src"/parallelize/run" $dst
cp $src"/parallelize/run-rr.py" $dst$folder
cd $dst
echo $PWD
./cp_script $folder
for (( i=1; i<=1000; i++ ))
do  
  echo "Running at iteration "$i
  echo "source: "$src
  cd $src
  echo $PWD
  python3 static_dep_graph.py >> out
  mv rr_inputs $dst
  cd $dst
  ./run $folder $1
  python3 combine.py $folder $src $1
  python3 rename.py $i $folder
  cp $dst"rr_results.json" $src"/cache/rr_results_"$1".json" #the program name
done
