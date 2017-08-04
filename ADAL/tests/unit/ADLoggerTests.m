// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

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
    
    [ADLogger setNSLogging:YES];//We disable it by default in the rest of the tests to limit the log files
    XCTAssertTrue([ADLogger getNSLogging]);
}

- (void)tearDown
{
    [super tearDown];
}

- (void)testMessageNoThrowing
{
    //Neither of these calls should throw. See the method body for details:
    [ADLogger log:ADAL_LOG_LEVEL_NO_LOG context:nil message:@"Message" errorCode:AD_ERROR_SUCCEEDED info:@"info" correlationId:nil userInfo:nil];
    [ADLogger log:ADAL_LOG_LEVEL_ERROR context:nil message:nil errorCode:AD_ERROR_SUCCEEDED info:@"info" correlationId:nil userInfo:nil];
    [ADLogger log:ADAL_LOG_LEVEL_ERROR context:nil message:@"message" errorCode:AD_ERROR_SUCCEEDED info:nil correlationId:nil userInfo:nil];
}

@end
