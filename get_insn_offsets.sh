#!/bin/bash
file_lines=()
while read -r line; do
    file_lines+=($line)
done < $1

for file_line in "${file_lines[@]}"
do
    gdb ./$2 -ex '"'"info line "$file_line'"' --batch
    echo "DELIMINATOR"
done
echo "FIN" >> $1"_DONE"
scp $1".out" $3
scp $1"_DONE" $3
rm $1"
rm $1".out"
rm $1"_DONE"
