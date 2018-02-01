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
#import "ADLogger.h"

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
    
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    [ADLogger setLogCallBack:nil];
#pragma clang diagnostic pop
    
    [ADLogger setLoggerCallback:nil];
    [ADLogger setPiiEnabled:NO];
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

- (void)testLog_whenPiiNotEnabled_andLogMessage_shouldReturnMessageInCallback
{
    XCTestExpectation* expectation = [self expectationWithDescription:@"Validate logger callback."];
    
    [ADLogger setLoggerCallback:^(ADAL_LOG_LEVEL logLevel, NSString *message, BOOL containsPii)
     {
         XCTAssertNotNil(message);
         XCTAssertEqual(logLevel, ADAL_LOG_LEVEL_ERROR);
         XCTAssertFalse(containsPii);
         
         [expectation fulfill];
     }];
    
    [[MSIDLogger sharedLogger] logLevel:MSIDLogLevelError context:nil correlationId:nil isPII:NO format:@"message"];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
}

- (void)testLog_whenPiiEnabled_andLogPii_shouldReturnMessageInCallback
{
    [ADLogger setPiiEnabled:YES];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"Validate logger callback."];
    
    [ADLogger setLoggerCallback:^(ADAL_LOG_LEVEL logLevel, NSString *message, BOOL containsPii)
     {
         XCTAssertNotNil(message);
         XCTAssertEqual(logLevel, ADAL_LOG_LEVEL_ERROR);
         XCTAssertFalse(containsPii);
         
         [expectation fulfill];
     }];
    
    [[MSIDLogger sharedLogger] logLevel:MSIDLogLevelError context:nil correlationId:nil isPII:NO format:@"message"];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
}

- (void)testLog_whenPiiNotEnabled_andLogPii_shouldNotInvokeCallback
{
    XCTestExpectation* expectation = [self expectationWithDescription:@"Validate logger callback."];
    expectation.inverted = YES;
    
    [ADLogger setLoggerCallback:^(ADAL_LOG_LEVEL __unused logLevel, NSString __unused *message, BOOL __unused containsPii)
     {
         [expectation fulfill];
     }];
    
    [[MSIDLogger sharedLogger] logLevel:MSIDLogLevelError context:nil correlationId:nil isPII:YES format:@"message"];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
}

- (void)testLog_whenPiiNotEnabled_andOldCallback_andLogMessage_shouldReturnMessageInCallback
{
    XCTestExpectation* expectation = [self expectationWithDescription:@"Validate logger callback."];
    
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    
    [ADLogger setLogCallBack:^(ADAL_LOG_LEVEL logLevel, NSString *message, NSString *additionalInfo, __unused NSInteger errorCode, __unused NSDictionary *userInfo)
    {
         XCTAssertNotNil(message);
         XCTAssertEqual(logLevel, ADAL_LOG_LEVEL_ERROR);
         XCTAssertNil(additionalInfo);
         
         [expectation fulfill];
     }];
    
#pragma clang diagnostic pop
    
    [[MSIDLogger sharedLogger] logLevel:MSIDLogLevelError context:nil correlationId:nil isPII:NO format:@"message"];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
}

- (void)testLog_whenPiiEnabled_andOldCallback_andLogPii_shouldReturnAdditionalMessageInCallback
{
    [ADLogger setPiiEnabled:YES];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"Validate logger callback."];
    
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    
    [ADLogger setLogCallBack:^(ADAL_LOG_LEVEL logLevel, NSString *message, NSString *additionalInfo, NSInteger errorCode, NSDictionary *userInfo)
     {
         XCTAssertNil(userInfo);
         XCTAssertEqual(errorCode, 0);
         XCTAssertNotNil(additionalInfo);
         XCTAssertEqualObjects(message, @"PII message");
         XCTAssertEqual(logLevel, ADAL_LOG_LEVEL_ERROR);
         XCTAssertNil(userInfo);
         
         [expectation fulfill];
     }];
    
#pragma clang diagnostic pop
    
    [[MSIDLogger sharedLogger] logLevel:MSIDLogLevelError context:nil correlationId:nil isPII:YES format:@"message"];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
}

- (void)testLog_whenPiiNotEnabled_andOldCallback_andLogPii_shouldNotInvokeCallback
{
    XCTestExpectation* expectation = [self expectationWithDescription:@"Validate logger callback."];
    expectation.inverted = YES;
    
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    
    [ADLogger setLogCallBack:^(__unused ADAL_LOG_LEVEL logLevel, __unused NSString *message, __unused NSString *additionalInfo, __unused NSInteger errorCode, __unused NSDictionary *userInfo)
    {
         [expectation fulfill];
     }];
    
#pragma clang diagnostic pop
    
    [[MSIDLogger sharedLogger] logLevel:MSIDLogLevelError context:nil correlationId:nil isPII:YES format:@"message"];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
}

- (void)testLog_whenBothCallbacksSet_shouldCallNewOne
{
    XCTestExpectation *oldExpectation = [self expectationWithDescription:@"Validate old logger callback."];
    oldExpectation.inverted = YES;
    
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    
    [ADLogger setLogCallBack:^(__unused ADAL_LOG_LEVEL logLevel, __unused NSString *message, __unused NSString *additionalInfo, __unused NSInteger errorCode, __unused NSDictionary *userInfo)
     {
         [oldExpectation fulfill];
     }];
    
#pragma clang diagnostic pop
    
    XCTestExpectation *newExpectation = [self expectationWithDescription:@"Validate new logger callback."];
    
    [ADLogger setLoggerCallback:^(ADAL_LOG_LEVEL logLevel, NSString *message, BOOL containsPii)
     {
         XCTAssertNotNil(message);
         XCTAssertEqual(logLevel, ADAL_LOG_LEVEL_ERROR);
         XCTAssertFalse(containsPii);
         
         [newExpectation fulfill];
     }];
    
    
    [[MSIDLogger sharedLogger] logLevel:MSIDLogLevelError context:nil correlationId:nil isPII:NO format:@"message"];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
}

@end
