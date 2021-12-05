while true
do
	hwclock >> history
	pmap -x $1 | grep total >> history
	sleep 1
done
