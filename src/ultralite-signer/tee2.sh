#!/bin/bash

if [ -z "$1" ]; then
    base="."  # default base path is current directory
else
    base="$1"
fi
prefix=$2     # default prefix is an empty string
postfix=$3    # default postfix is an empty string

while read line;
do
    day=${line:3:10} # expects to find 'yyyy-MM-dd' at offset 3 in line
    month=${day:0:7} # expects to find 'yyyy-MM'    at offset 0 in day
    directory="$base/$month"
    logname="$prefix$day$postfix"
    path="$directory/$logname"
    if [ ! -d "$directory" ]; then
	mkdir "$directory"  # need to create the directory if it doesn't exist
    fi
    echo "$line"            # echo to stdout
    echo "$line" >> "$path" # cat to the logfile
done
