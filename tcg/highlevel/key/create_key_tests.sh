#!/bin/sh
#
# Create a key of each type possible
#

TEST=./Tspi_Key_CreateKey04

for TYPE in legacy bind signing;do
	for SIZE in 512 1024 2048;do
		echo "$TEST -t $TYPE -s $SIZE -m -v -a"
		$TEST -t $TYPE -s $SIZE -m -v -a
		echo "$TEST -t $TYPE -s $SIZE -m -a"
		$TEST -t $TYPE -s $SIZE -m -a
		echo "$TEST -t $TYPE -s $SIZE -v -a"
		$TEST -t $TYPE -s $SIZE -v -a
		echo "$TEST -t $TYPE -s $SIZE -a"
		$TEST -t $TYPE -s $SIZE -a
		echo "$TEST -t $TYPE -s $SIZE -m -v"
		$TEST -t $TYPE -s $SIZE -m -v
		echo "$TEST -t $TYPE -s $SIZE -m"
		$TEST -t $TYPE -s $SIZE -m
		echo "$TEST -t $TYPE -s $SIZE -v"
		$TEST -t $TYPE -s $SIZE -v
		echo "$TEST -t $TYPE -s $SIZE"
		$TEST -t $TYPE -s $SIZE
	done
done

# Do storage keys manually, since only size 2048 is valid
echo "$TEST -t storage -s 2048 -m -v -a"
$TEST -t storage -s 2048 -m -v -a
echo "$TEST -t storage -s 2048 -m -a"
$TEST -t storage -s 2048 -m -a
echo "$TEST -t storage -s 2048 -v -a"
$TEST -t storage -s 2048 -v -a
echo "$TEST -t storage -s 2048 -a"
$TEST -t storage -s 2048 -a
echo "$TEST -t storage -s 2048 -m -v"
$TEST -t storage -s 2048 -m -v
echo "$TEST -t storage -s 2048 -m"
$TEST -t storage -s 2048 -m
echo "$TEST -t storage -s 2048 -v"
$TEST -t storage -s 2048 -v
echo "$TEST -t storage -s 2048"
$TEST -t storage -s 2048
