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
mv $1".out" $1".out.1"
mv $1".DONE" $1".DONE.1"
scp $1".out.1" $3$1".out"
scp $1"_DONE.1" $3$1"_DONE"
rm $1
rm $1".out.1"
rm $1"_DONE.1"
