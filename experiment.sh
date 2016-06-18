#!/bin/bash
for bin in ./bin/*
do
    if file "$bin" | grep -q "executable" 
    then
    	basename $bin
    	lib=`echo "$bin" | cut -d '-' -f2`
    	for sig in ./sig/*"$lib"-*
    	do
    	python lscan.py -f "$bin" -s "$sig"
    	done
    	echo ""
    fi
done