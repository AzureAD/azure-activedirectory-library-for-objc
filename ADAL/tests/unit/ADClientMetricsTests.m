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
#import "ADClientMetrics.h"
#import "XCTestCase+TestHelperMethods.h"

@interface ADClientMetricsTests : ADTestCase

@end

@implementation ADClientMetricsTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

#pragma mark - addClientMetrics

- (void)testAddClientMetrics_whenNoMetrics_shouldNotModifyHeader
{
    ADClientMetrics *metrics = [ADClientMetrics new];
    NSMutableDictionary *header = [NSMutableDictionary new];
    
    [metrics addClientMetrics:header endpoint:@"https://login.windows.net/common/oauth2/token"];
    
    XCTAssertEqual([header count], 0);
}

- (void)testAddClientMetrics_whenMetricsAreStored_shouldAddMetricsToHeader
{
    ADClientMetrics *metrics = [ADClientMetrics new];
    NSMutableDictionary *header = [NSMutableDictionary new];
    NSUUID *correlationId = [[NSUUID alloc] initWithUUIDString:@"3FBD4165-1CA5-436D-A2C7-15EF855F6893"];
    [metrics endClientMetricsRecord:@"https://login.windows.net/common/oauth2/token"
                          startTime:[NSDate new]
                      correlationId:correlationId
                       errorDetails:@"error"];
    
    [metrics addClientMetrics:header endpoint:@"https://login.windows.net/common/oauth2/token"];
    
    XCTAssertEqual([header count], 4);
    ADAssertStringEquals(header[@"x-client-last-endpoint"], @"token");
    ADAssertStringEquals(header[@"x-client-last-error"], @"error");
    ADAssertStringEquals(header[@"x-client-last-request"], @"3FBD4165-1CA5-436D-A2C7-15EF855F6893");
    XCTAssertNotNil(header[@"x-client-last-response-time"]);
}

- (void)testAddClientMetrics_whenMetricsAreStored_shouldClearStoredMetrics
{
    ADClientMetrics *metrics = [ADClientMetrics new];
    NSMutableDictionary *header = [NSMutableDictionary new];
    NSUUID *correlationId = [[NSUUID alloc] initWithUUIDString:@"3FBD4165-1CA5-436D-A2C7-15EF855F6893"];
    [metrics endClientMetricsRecord:@"https://login.windows.net/common/oauth2/token"
                          startTime:[NSDate new]
                      correlationId:correlationId
                       errorDetails:@"error"];
    
    [metrics addClientMetrics:header endpoint:@"https://login.windows.net/common/oauth2/token"];
    
    XCTAssertNil(metrics.endpoint);
    XCTAssertNil(metrics.correlationId);
    XCTAssertNil(metrics.errorToReport);
    XCTAssertNil(metrics.responseTime);
}

- (void)testAddClientMetrics_whenMetricsAreStoredWithADFSEndpoint_shouldNotAddMetricsToHeader
{
    ADClientMetrics *metrics = [ADClientMetrics new];
    NSMutableDictionary *header = [NSMutableDictionary new];
    NSUUID *correlationId = [[NSUUID alloc] initWithUUIDString:@"3FBD4165-1CA5-436D-A2C7-15EF855F6893"];
    [metrics endClientMetricsRecord:@"https://login.windows.net/common/oauth2/token"
                          startTime:[NSDate new]
                      correlationId:correlationId
                       errorDetails:@"error"];
    
    [metrics addClientMetrics:header endpoint:@"https://sts.contoso.com/adfs/oauth2/token"];
    
    XCTAssertEqual([header count], 0);
}

#pragma mark - endClientMetricsRecord

- (void)testEndClientMetricsRecord_whenMetricsAreProvided_shouldStoreThem
{
    ADClientMetrics *metrics = [ADClientMetrics new];
    NSDate *startTime = [NSDate new];
    NSUUID *correlationId = [[NSUUID alloc] initWithUUIDString:@"3FBD4165-1CA5-436D-A2C7-15EF855F6893"];
    
    [metrics endClientMetricsRecord:@"https://login.windows.net/common/oauth2/token"
                          startTime:startTime
                      correlationId:correlationId
                       errorDetails:@"error"];
    
    ADAssertStringEquals(metrics.endpoint, @"https://login.windows.net/common/oauth2/token");
    ADAssertStringEquals(metrics.correlationId, @"3FBD4165-1CA5-436D-A2C7-15EF855F6893");
    ADAssertStringEquals(metrics.errorToReport, @"error");
    XCTAssertNotNil(metrics.responseTime);
}

- (void)testEndClientMetricsRecord_whenMetricsAreProvidedWithADFSEndpoint_shouldNotStoreThem
{
    ADClientMetrics *metrics = [ADClientMetrics new];
    NSDate *startTime = [NSDate new];
    NSUUID *correlationId = [[NSUUID alloc] initWithUUIDString:@"3FBD4165-1CA5-436D-A2C7-15EF855F6893"];
    
    [metrics endClientMetricsRecord:@"https://sts.contoso.com/adfs/oauth2/token"
                          startTime:startTime
                      correlationId:correlationId
                       errorDetails:@"error"];
    
    XCTAssertNil(metrics.endpoint);
    XCTAssertNil(metrics.correlationId);
    XCTAssertNil(metrics.errorToReport);
    XCTAssertNil(metrics.responseTime);
}

@end
