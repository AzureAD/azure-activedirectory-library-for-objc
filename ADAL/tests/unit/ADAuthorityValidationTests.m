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


#import "ADAuthenticationContext.h"
#import "ADAuthenticationResult.h"
#import "ADAuthorityValidation.h"
#import "ADAuthorityValidationRequest.h"
#import "ADDrsDiscoveryRequest.h"
#import "ADTestURLSession.h"
#import "ADTestURLSession.h"

#import "ADUserIdentifier.h"
#import "ADWebFingerRequest.h"
#import "XCTestCase+TestHelperMethods.h"
#import <XCTest/XCTest.h>

@interface ADAuthortyValidationTests : XCTestCase

@end

@implementation ADAuthortyValidationTests

- (void)setUp {
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

- (void)testIsAADAuthorityValidated
{
    ADAuthorityValidation* authorityValidation = [[ADAuthorityValidation alloc] init];
    
    XCTAssertFalse([authorityValidation isAuthorityValidated:nil]);
    XCTAssertFalse([authorityValidation isAuthorityValidated:[NSURL URLWithString:@"  "]]);
    NSURL* anotherHost = [NSURL URLWithString:@"https://somedomain.com"];
    XCTAssertFalse([authorityValidation isAuthorityValidated:anotherHost]);
}

- (void)testAdfsAuthorityValidated
{
    ADAuthorityValidation* authorityValidation = [[ADAuthorityValidation alloc] init];
    
    NSURL* anotherHost = [NSURL URLWithString:@"https://somedomain.com"];
    NSString* upnSuffix = @"user@foo.com";
    
    XCTAssertFalse([authorityValidation isAuthorityValidated:nil domain:upnSuffix]);
    XCTAssertFalse([authorityValidation isAuthorityValidated:anotherHost domain:nil]);
    XCTAssertFalse([authorityValidation isAuthorityValidated:anotherHost domain:upnSuffix]);
}

- (void)testAddAdfsAuthority
{
    ADAuthorityValidation* authorityValidation = [[ADAuthorityValidation alloc] init];
    
    NSURL* anotherHost = [NSURL URLWithString:@"https://somedomain.com"];
    NSString* upnSuffix = @"user@foo.com";
    
    [authorityValidation addValidAuthority:anotherHost domain:upnSuffix];
    
    XCTAssertFalse([authorityValidation isAuthorityValidated:nil domain:upnSuffix]);
    XCTAssertFalse([authorityValidation isAuthorityValidated:anotherHost domain:nil]);
    XCTAssertTrue([authorityValidation isAuthorityValidated:anotherHost domain:upnSuffix]);
}

@end
