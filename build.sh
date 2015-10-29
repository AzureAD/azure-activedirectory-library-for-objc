#!/bin/sh

xcodebuild test -project ADALiOS/ADALiOS.xcodeproj -scheme ADALiOS -configuration CodeCoverage -sdk iphonesimulator ONLY_ACTIVE_ARCH=NO GCC_INSTRUMENT_PROGRAM_FLOW_ARCS=YES GCC_GENERATE_TEST_COVERAGE_FILES=YES -destination 'platform=iOS Simulator,name=iPhone 6,OS=latest' | xcpretty -c
xcodebuild -workspace ADALiOS.xcworkspace -scheme MyTestiOSApp -configuration CodeCoverage -sdk iphonesimulator ONLY_ACTIVE_ARCH=NO GCC_INSTRUMENT_PROGRAM_FLOW_ARCS=YES GCC_GENERATE_TEST_COVERAGE_FILES=YES -destination 'platform=iOS Simulator,name=iPhone 6,OS=latest' | xcpretty -c

slather coverage -s ADALiOS/ADALiOS.xcodeproj