// Copyright © Microsoft Open Technologies, Inc.
//
// All Rights Reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
// ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
// PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
//
// See the Apache License, Version 2.0 for the specific language
// governing permissions and limitations under the License.

#import <XCTest/XCTest.h>
#import "XCTestCase+TestHelperMethods.h"
#import <libkern/OSAtomic.h>

const int sMaxLoggerThreadsDuration = 5;//In seconds
const int sMaxLoggerTestThreads = 100;
volatile int32_t sLoggerTestThreadsCompleted = 0;
dispatch_semaphore_t sLoggerTestCompletedSignal;

@interface ADLoggerTests : XCTestCase

@end

@implementation ADLoggerTests

- (void)setUp
{
    [super setUp];
    // Put setup code here; it will be run once, before the first test case.
    [self adTestBegin:ADAL_LOG_LEVEL_INFO];
    [ADLogger setNSLogging:YES];//We disable it by default in the rest of the tests to limit the log files
    XCTAssertTrue([ADLogger getNSLogging]);
}

- (void)tearDown
{
    // Put teardown code here; it will be run once, after the last test case.
    [self adTestEnd];
    [super tearDown];
}

- (void)testMessageNoThrowing
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    //Neither of these calls should throw. See the method body for details:
    [ADLogger log:ADAL_LOG_LEVEL_NO_LOG message:@"Message" errorCode:AD_ERROR_SUCCEEDED info:@"info" correlationId:nil];
    [ADLogger log:ADAL_LOG_LEVEL_ERROR message:nil errorCode:AD_ERROR_SUCCEEDED info:@"info" correlationId:nil];
    [ADLogger log:ADAL_LOG_LEVEL_ERROR message:@"message" errorCode:AD_ERROR_SUCCEEDED info:nil correlationId:nil];
}

@end
