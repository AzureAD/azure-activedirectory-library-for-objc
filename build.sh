#!/bin/sh

find . -name "*.gcda" -print0 | xargs -0 rm

./build/iOS_Static_Lib
./build/iOS_Test_App
./build/Mac_Framework
./build/Mac_Test_App
./build/Mac_32_bit

# slather coverage -s ADAL/ADAL.xcodeproj