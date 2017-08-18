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

@interface ADLoggerTests : ADTestCase

@property (nonatomic) BOOL enableNSLogging;

@end

@implementation ADLoggerTests

- (void)setUp
{
    [super setUp];
    
    self.enableNSLogging = [ADLogger getNSLogging];
    [ADLogger setNSLogging:YES];
}

- (void)tearDown
{
    [super tearDown];
    
    [ADLogger setNSLogging:self.enableNSLogging];
}

#pragma mark - setNSLogging

- (void)testSetNSLogging_whenValueTrue_shouldReturnTrueInGetNSLogging
{
    [ADLogger setNSLogging:YES];
    
    XCTAssertTrue([ADLogger getNSLogging]);
}

- (void)testSetNSLogging_whenValueFalse_shouldReturnfalseInGetNSLogging
{
    [ADLogger setNSLogging:NO];
    
    XCTAssertFalse([ADLogger getNSLogging]);
}

#pragma mark - log:context:message:errorCode:info:correlationId:userInfo

- (void)testLog_whenLogLevelNoMessageValidInfoValid_shouldNotThrow
{
    [ADLogger log:ADAL_LOG_LEVEL_NO_LOG context:nil message:@"Message" errorCode:AD_ERROR_SUCCEEDED info:@"info" correlationId:nil userInfo:nil];
}

- (void)testLog_whenLogLevelErrorMessageNilInfoValid_shouldNotThrow
{
    [ADLogger log:ADAL_LOG_LEVEL_ERROR context:nil message:nil errorCode:AD_ERROR_SUCCEEDED info:@"info" correlationId:nil userInfo:nil];
}

- (void)testLog_whenLogLevelErrorMessageValidInfoNil_shouldNotThrow
{
    [ADLogger log:ADAL_LOG_LEVEL_ERROR context:nil message:@"message" errorCode:AD_ERROR_SUCCEEDED info:nil correlationId:nil userInfo:nil];
}

@end
