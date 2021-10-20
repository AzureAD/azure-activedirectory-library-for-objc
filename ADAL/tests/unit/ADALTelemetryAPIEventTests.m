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
#import "ADALTelemetryAPIEvent.h"
#import "XCTestCase+TestHelperMethods.h"
#import "MSIDTelemetryEventStrings.h"
#import "NSData+MSIDExtensions.h"

@interface ADALTelemetryAPIEventTests : ADTestCase

@end

@implementation ADALTelemetryAPIEventTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

- (void)testSetUserInformation_whenUserIdProvided_shouldHashUserId
{
    NSUUID *correlationId = [NSUUID UUID];
    ADALTelemetryAPIEvent *event = [[ADALTelemetryAPIEvent alloc] initWithName:@"testEvent1"
                                                                 requestId:@"requestId"
                                                             correlationId:correlationId];
    ADALUserInformation *userInfo = [self adCreateUserInformation:@"eric_cartman@contoso.com"];
    
    [event setUserInformation:userInfo];
    
    ADAssertStringEquals([event propertyWithName:MSID_TELEMETRY_KEY_USER_ID],
                         [NSString msidHexStringFromData:[[@"eric_cartman@contoso.com" dataUsingEncoding:NSUTF8StringEncoding] msidSHA256]]);
}

- (void)testSetUserInformation_whenTenantIdProvided_shouldNotHashTenantIdAsItIsOii
{
    NSUUID *correlationId = [NSUUID UUID];
    ADALTelemetryAPIEvent *event = [[ADALTelemetryAPIEvent alloc] initWithName:@"testEvent1"
                                                                 requestId:@"requestId"
                                                             correlationId:correlationId];
    ADALUserInformation *userInfo = [self adCreateUserInformation:@"eric_cartman@contoso.com"];
    
    [event setUserInformation:userInfo];
    
    ADAssertStringEquals([event propertyWithName:MSID_TELEMETRY_KEY_TENANT_ID], @"6fd1f5cd-a94c-4335-889b-6c598e6d8048");
}

- (void)testSetUserId_whenUserIdValid_shouldHashUserId
{
    NSUUID *correlationId = [NSUUID UUID];
    ADALTelemetryAPIEvent *event = [[ADALTelemetryAPIEvent alloc] initWithName:@"testEvent1"
                                                                 requestId:@"requestId"
                                                             correlationId:correlationId];
    
    [event setUserId:@"eric_cartman@contoso.com"];
    
    ADAssertStringEquals([event propertyWithName:MSID_TELEMETRY_KEY_USER_ID], [NSString msidHexStringFromData:[[@"eric_cartman@contoso.com" dataUsingEncoding:NSUTF8StringEncoding] msidSHA256]]);
}

@end
