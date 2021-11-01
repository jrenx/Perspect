cd /home/renxian2/eval_mongodb_44991
pkill python3 -u renxian2
pkill para -u renxian2
git pull
cd /home/renxian2/eval_mongodb_44991/preprocessor
make clean
make
cd ..
cd /home/renxian2/eval_mongodb_44991/pin
make PIN_ROOT=~/pin-3.11
exit
