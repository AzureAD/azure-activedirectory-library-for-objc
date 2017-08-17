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
#import "ADTelemetryHttpEvent.h"
#import "ADTelemetry.h"
#import "ADTelemetry+Internal.h"

@interface ADTelemetryHttpEventTests : ADTestCase

@end

@implementation ADTelemetryHttpEventTests

- (void)testSetClientTelemetry_whenNilTelemetry_shouldNotUpdateProperties
{
    NSString *requestId = [[ADTelemetry sharedInstance] registerNewRequest];
    
    ADTelemetryHttpEvent *httpEvent = [[ADTelemetryHttpEvent alloc] initWithName:@"httpEvent"
                                                                        requestId:requestId
                                                                    correlationId:nil];
    
    [httpEvent setClientTelemetry:nil];
    XCTAssertNil([[httpEvent getProperties] objectForKey:@"Microsoft.ADAL.server_error_code"]);
    XCTAssertNil([[httpEvent getProperties] objectForKey:@"Microsoft.ADAL.server_sub_error_code"]);
    XCTAssertNil([[httpEvent getProperties] objectForKey:@"Microsoft.ADAL.rt_age"]);
    XCTAssertNil([[httpEvent getProperties] objectForKey:@"Microsoft.ADAL.spe_info"]);
}

- (void)testSetClientTelemetry_whenBlankTelemetry_shouldNotUpdateProperties
{
    NSString *requestId = [[ADTelemetry sharedInstance] registerNewRequest];
    
    ADTelemetryHttpEvent *httpEvent = [[ADTelemetryHttpEvent alloc] initWithName:@"httpEvent"
                                                                       requestId:requestId
                                                                   correlationId:nil];
    
    [httpEvent setClientTelemetry:@" "];
    XCTAssertNil([[httpEvent getProperties] objectForKey:@"Microsoft.ADAL.server_error_code"]);
    XCTAssertNil([[httpEvent getProperties] objectForKey:@"Microsoft.ADAL.server_sub_error_code"]);
    XCTAssertNil([[httpEvent getProperties] objectForKey:@"Microsoft.ADAL.rt_age"]);
    XCTAssertNil([[httpEvent getProperties] objectForKey:@"Microsoft.ADAL.spe_info"]);
}

- (void)testSetClientTelemetry_whenTooLittleComponents_shouldNotUpdateProperties
{
    NSString *requestId = [[ADTelemetry sharedInstance] registerNewRequest];
    
    ADTelemetryHttpEvent *httpEvent = [[ADTelemetryHttpEvent alloc] initWithName:@"httpEvent"
                                                                       requestId:requestId
                                                                   correlationId:nil];
    
    [httpEvent setClientTelemetry:@"2,0,0"];
    XCTAssertNil([[httpEvent getProperties] objectForKey:@"Microsoft.ADAL.server_error_code"]);
    XCTAssertNil([[httpEvent getProperties] objectForKey:@"Microsoft.ADAL.server_sub_error_code"]);
    XCTAssertNil([[httpEvent getProperties] objectForKey:@"Microsoft.ADAL.rt_age"]);
    XCTAssertNil([[httpEvent getProperties] objectForKey:@"Microsoft.ADAL.spe_info"]);
}

- (void)testSetClientTelemetry_whenTooManyComponents_shouldNotUpdateProperties
{
    NSString *requestId = [[ADTelemetry sharedInstance] registerNewRequest];
    
    ADTelemetryHttpEvent *httpEvent = [[ADTelemetryHttpEvent alloc] initWithName:@"httpEvent"
                                                                       requestId:requestId
                                                                   correlationId:nil];
    
    [httpEvent setClientTelemetry:@"2,0,0,0,0,0,1234,"];
    XCTAssertNil([[httpEvent getProperties] objectForKey:@"Microsoft.ADAL.server_error_code"]);
    XCTAssertNil([[httpEvent getProperties] objectForKey:@"Microsoft.ADAL.server_sub_error_code"]);
    XCTAssertNil([[httpEvent getProperties] objectForKey:@"Microsoft.ADAL.rt_age"]);
    XCTAssertNil([[httpEvent getProperties] objectForKey:@"Microsoft.ADAL.spe_info"]);
}

- (void)testSetClientTelemetry_whenWrongVersionNumber_shouldNotUpdateProperties
{
    NSString *requestId = [[ADTelemetry sharedInstance] registerNewRequest];
    
    ADTelemetryHttpEvent *httpEvent = [[ADTelemetryHttpEvent alloc] initWithName:@"httpEvent"
                                                                       requestId:requestId
                                                                   correlationId:nil];
    
    [httpEvent setClientTelemetry:@"2,0,0,255.0643,"];
    XCTAssertNil([[httpEvent getProperties] objectForKey:@"Microsoft.ADAL.server_error_code"]);
    XCTAssertNil([[httpEvent getProperties] objectForKey:@"Microsoft.ADAL.server_sub_error_code"]);
    XCTAssertNil([[httpEvent getProperties] objectForKey:@"Microsoft.ADAL.rt_age"]);
    XCTAssertNil([[httpEvent getProperties] objectForKey:@"Microsoft.ADAL.spe_info"]);
}

- (void)testSetClientTelemetry_whenAllComponentsNoSPEInfo_shouldUpdateProperties
{
    NSString *requestId = [[ADTelemetry sharedInstance] registerNewRequest];
    
    ADTelemetryHttpEvent *httpEvent = [[ADTelemetryHttpEvent alloc] initWithName:@"httpEvent"
                                                                       requestId:requestId
                                                                   correlationId:nil];
    
    [httpEvent setClientTelemetry:@"1,123,1234,255.0643,"];
    XCTAssertEqualObjects([[httpEvent getProperties] objectForKey:@"Microsoft.ADAL.server_error_code"], @"123");
    XCTAssertEqualObjects([[httpEvent getProperties] objectForKey:@"Microsoft.ADAL.server_sub_error_code"], @"1234");
    XCTAssertEqualObjects([[httpEvent getProperties] objectForKey:@"Microsoft.ADAL.rt_age"], @"255.0643");
    XCTAssertEqualObjects([[httpEvent getProperties] objectForKey:@"Microsoft.ADAL.spe_info"], @"");
}

- (void)testSetClientTelemetry_whenAllComponentsWithSPEInfo_shouldUpdateProperties
{
    NSString *requestId = [[ADTelemetry sharedInstance] registerNewRequest];
    
    ADTelemetryHttpEvent *httpEvent = [[ADTelemetryHttpEvent alloc] initWithName:@"httpEvent"
                                                                       requestId:requestId
                                                                   correlationId:nil];
    
    [httpEvent setClientTelemetry:@"1,123,1234,255.0643,I"];
    XCTAssertEqualObjects([[httpEvent getProperties] objectForKey:@"Microsoft.ADAL.server_error_code"], @"123");
    XCTAssertEqualObjects([[httpEvent getProperties] objectForKey:@"Microsoft.ADAL.server_sub_error_code"], @"1234");
    XCTAssertEqualObjects([[httpEvent getProperties] objectForKey:@"Microsoft.ADAL.rt_age"], @"255.0643");
    XCTAssertEqualObjects([[httpEvent getProperties] objectForKey:@"Microsoft.ADAL.spe_info"], @"I");
}

@end
