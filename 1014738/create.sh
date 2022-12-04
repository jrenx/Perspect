x=1
str="a/"
while [ $x -le 3000 ]
do
	x=$(( $x + 1 ))
	str="${str}${str}"
	mkdir $str
done
