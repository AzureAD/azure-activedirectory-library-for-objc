#!/bin/sh

find . -name "*.gcda" -print0 | xargs -0 rm

xcodebuild test -workspace ADAL.xcworkspace -scheme ADAL -configuration CodeCoverage -sdk iphonesimulator ONLY_ACTIVE_ARCH=NO GCC_INSTRUMENT_PROGRAM_FLOW_ARCS=YES GCC_GENERATE_TEST_COVERAGE_FILES=YES -destination 'platform=iOS Simulator,name=iPhone 6,OS=latest' | xcpretty
xcodebuild build -workspace ADAL.xcworkspace -scheme MyTestiOSApp -configuration CodeCoverage -sdk iphonesimulator ONLY_ACTIVE_ARCH=NO -destination 'platform=iOS Simulator,name=iPhone 6,OS=latest' | xcpretty
xcodebuild test -workspace ADAL.xcworkspace -scheme "ADAL Mac" | xcpretty
xcodebuild test -workspace ADAL.xcworkspace -scheme "ADAL Mac" CURRENT_ARCH=i386 | xcpretty

# slather coverage -s ADAL/ADAL.xcodeproj