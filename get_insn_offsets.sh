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
mv $1".out" $1".out.1"
mv $1".DONE" $1".DONE.1"
scp $1".out.1" $3".out"
scp $1"_DONE.1" $3"_DONE"
rm $1
rm $1".out.1"
rm $1"_DONE.1"
