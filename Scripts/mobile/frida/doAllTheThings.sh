#!/bin/bash
mkdir work
for i in $(adb exec-out pm list packages | awk -F':' '{print $2}'); do 
	echo $i
	thepath=$(adb exec-out pm path $i | awk -F':' '{print $2}')
	echo $thepath
	if [[ $thepath =~ "system/priv-app" ]]
	then
	   adb pull $thepath work
	fi
done

for file in work/*
do
apktool d $file
done