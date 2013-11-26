// Created by Boris Vidolov on 10/26/13.
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

@interface ADLoggerTests : XCTestCase

@end

@implementation ADLoggerTests

- (void)setUp
{
    [super setUp];
    // Put setup code here; it will be run once, before the first test case.
    [self adTestBegin];
}

- (void)tearDown
{
    // Put teardown code here; it will be run once, after the last test case.
    [self adTestEnd];
    [super tearDown];
}

- (void)testLevel
{
    for(int i = ADAL_LOG_LEVEL_NO_LOG; i < ADAL_LOG_LAST; ++i)
    {
        [ADLogger setLevel:i];
        XCTAssertEqual(i, [ADLogger getLevel], "Level not set");
        for(int j = ADAL_LOG_LEVEL_ERROR; j < ADAL_LOG_LAST; ++j)
        {
            NSString* message = [NSString stringWithFormat:@"Test%dMessage%d %s", i, j, __PRETTY_FUNCTION__];
            NSString* info = [NSString stringWithFormat:@"Test%dnfo%d %s", i, j, __PRETTY_FUNCTION__];
            [ADLogger log:j message:message additionalInformation:info errorCode:1];
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
    //Neither of these calls should throw. See the method body for details:
    [ADLogger log:ADAL_LOG_LEVEL_NO_LOG message:@"Message" additionalInformation:@"info" errorCode:AD_ERROR_SUCCEEDED];
    [ADLogger log:ADAL_LOG_LEVEL_ERROR message:nil additionalInformation:@"info" errorCode:AD_ERROR_SUCCEEDED];
    [ADLogger log:ADAL_LOG_LEVEL_ERROR message:@"message" additionalInformation:nil errorCode:AD_ERROR_SUCCEEDED];
}

@end
