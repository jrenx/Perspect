x=1
str=""
while [ $x -le 3000 ]
do
	x=$(( $x + 1 ))
	str=$str"a/"
	mkdir $str
done
