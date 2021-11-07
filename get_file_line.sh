#!/bin/bash
insns=()
while read -r line; do
    insns+=($line)
done < $1

for insn in "${insns[@]}"
do
    addr2line -e $2 $insn
done
echo "FIN" >> $1"_DONE"
scp $1".out" $3
scp $1"_DONE" $3
rm $1
rm $1".out"
rm $1"_DONE"
