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


#import "ADALAuthenticationContext.h"
#import "ADALAuthenticationResult.h"
#import "ADALAuthorityValidation.h"
#import "ADALAuthorityValidationRequest.h"
#import "ADALDrsDiscoveryRequest.h"
#import "ADTestURLSession.h"
#import "ADTestURLSession.h"

#import "ADALUserIdentifier.h"
#import "ADALWebFingerRequest.h"

#import "XCTestCase+TestHelperMethods.h"

@interface ADAuthortyValidationTests : ADTestCase

@end

@implementation ADAuthortyValidationTests

- (void)setUp {
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

#pragma mark -
#pragma mark ADFS Validation Tests

- (void)testAdfsAuthorityValidated
{
    ADALAuthorityValidation* authorityValidation = [[ADALAuthorityValidation alloc] init];
    
    NSURL* anotherHost = [NSURL URLWithString:@"https://somedomain.com"];
    NSString* upnSuffix = @"user@foo.com";
    
    XCTAssertFalse([authorityValidation isAuthorityValidated:nil domain:upnSuffix]);
    XCTAssertFalse([authorityValidation isAuthorityValidated:anotherHost domain:nil]);
    XCTAssertFalse([authorityValidation isAuthorityValidated:anotherHost domain:upnSuffix]);
}

- (void)testAddAdfsAuthority
{
    ADALAuthorityValidation* authorityValidation = [[ADALAuthorityValidation alloc] init];
    
    NSURL* anotherHost = [NSURL URLWithString:@"https://somedomain.com"];
    NSString* upnSuffix = @"user@foo.com";
    
    [authorityValidation addValidAuthority:anotherHost domain:upnSuffix];
    
    XCTAssertFalse([authorityValidation isAuthorityValidated:nil domain:upnSuffix]);
    XCTAssertFalse([authorityValidation isAuthorityValidated:anotherHost domain:nil]);
    XCTAssertTrue([authorityValidation isAuthorityValidated:anotherHost domain:upnSuffix]);
}

@end
