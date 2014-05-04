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

- (void)testLevel
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    for(int i = ADAL_LOG_LEVEL_NO_LOG; i < ADAL_LOG_LAST; ++i)
    {
        [ADLogger setLevel:i];
        XCTAssertEqual(i, [ADLogger getLevel], "Level not set");
        for(int j = ADAL_LOG_LEVEL_ERROR; j <= ADAL_LOG_LAST; ++j)
        {
            NSString* message = [NSString stringWithFormat:@"Test%dMessage%d %s", i, j, __PRETTY_FUNCTION__];
            NSString* info = [NSString stringWithFormat:@"Test%dnfo%d %s", i, j, __PRETTY_FUNCTION__];
            [ADLogger log:j message:message errorCode:1 additionalInformation:info];
            if (j <= i)//Meets the error bar
            {
                ADAssertLogsContainValue(TEST_LOG_MESSAGE, message);
                ADAssertLogsContainValue(TEST_LOG_INFO, info);
            }
            else
            {
                ADAssertLogsDoNotContainValue(TEST_LOG_MESSAGE, message);
                ADAssertLogsDoNotContainValue(TEST_LOG_INFO, info);
            }
        }
    }
}

-(void) testMessageNoThrowing
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    //Neither of these calls should throw. See the method body for details:
    [ADLogger log:ADAL_LOG_LEVEL_NO_LOG message:@"Message" errorCode:AD_ERROR_SUCCEEDED additionalInformation:@"info" ];
    [ADLogger log:ADAL_LOG_LEVEL_ERROR message:nil errorCode:AD_ERROR_SUCCEEDED additionalInformation:@"info" ];
    [ADLogger log:ADAL_LOG_LEVEL_ERROR message:@"message" errorCode:AD_ERROR_SUCCEEDED additionalInformation:nil];
}

-(void) threadProc
{
    @autoreleasepool
    {
        __block NSMutableString* log = [NSMutableString new];
        NSDate* end = [NSDate dateWithTimeIntervalSinceNow:sMaxLoggerThreadsDuration];
        while([[NSDate dateWithTimeIntervalSinceNow:0] compare:end] != NSOrderedDescending)//Runs for sMaxLoggerThreadsDuration seconds
        {
            @autoreleasepool//Needed, as the code inside the loop creates objects:
            {
                [ADLogger setLogCallBack:nil];
                [ADLogger log:ADAL_LOG_LEVEL_INFO message:@"test" errorCode:1 additionalInformation:@"info"];
                [ADLogger setLogCallBack:^(ADAL_LOG_LEVEL logLevel, NSString *message, NSString *additionalInformation, NSInteger errorCode)
                 {
                     [log appendFormat:@"%d; %@; %@; %ld;", logLevel, message, additionalInformation, (long)errorCode];
                 }];
                [ADLogger log:ADAL_LOG_LEVEL_INFO message:@"test1" errorCode:1 additionalInformation:@"info1"];
                [ADLogger setLogCallBack:nil];
                NSRange all = {0, log.length};
                [log deleteCharactersInRange:all];//Clear to avoid memory spike
            }
        }
    }
    if (OSAtomicIncrement32(&sLoggerTestThreadsCompleted) == sMaxLoggerTestThreads)
    {
        dispatch_semaphore_signal(sLoggerTestCompletedSignal);
    }
}

//Runs multiple thread setting, clearing the log callback and logging simultaneously
//The logging should be as reliable as possible.
-(void) testSetCallbackMutlithreaded
{
    [ADLogger setNSLogging:NO];//Limit the system logs, as we will be printing tons of messsages here.
    sLoggerTestCompletedSignal = dispatch_semaphore_create(0);
    XCTAssertNotNil(sLoggerTestCompletedSignal);
    sLoggerTestThreadsCompleted = 0;
    for(int i = 0; i < sMaxLoggerTestThreads; ++i)
    {
        [self performSelectorInBackground:@selector(threadProc) withObject:self];
    }
    if (dispatch_semaphore_wait(sLoggerTestCompletedSignal, dispatch_time(DISPATCH_TIME_NOW, (sMaxLoggerThreadsDuration + 5)*NSEC_PER_SEC)))
    {
        XCTFail("Timed out. The threads did not complete smoothly. If the applicaiton has not crashed, this is an indication of a deadlock.");
    }
}

@end
