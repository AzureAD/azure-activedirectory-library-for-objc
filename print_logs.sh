#!/bin/bash

IFS=$(echo -en "\n\b")


for f in ~/Library/Developer/Xcode/DerivedData/*/Logs/Test/*/*/*/*/*/*; do
	bname=$(basename $f)
	echo "travis_fold:start:$bname"
	cat $f
	echo "travis_fold:end:$bname"
done

