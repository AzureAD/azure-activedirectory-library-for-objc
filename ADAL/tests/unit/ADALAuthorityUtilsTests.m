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
#import "ADALAuthorityUtils.h"

@interface ADALAuthorityUtilsTests : XCTestCase

@end

@implementation ADALAuthorityUtilsTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

- (void)testIsKnownHost_whenADTrustedAuthority_shuldReturnTrue
{
    XCTAssertTrue([ADALAuthorityUtils isKnownHost:[NSURL URLWithString:@"https://login.windows.net"]]);
}

- (void)testIsKnownHost_whenADTrustedAuthorityUS_shuldReturnTrue
{
    XCTAssertTrue([ADALAuthorityUtils isKnownHost:[NSURL URLWithString:@"https://login.microsoftonline.us"]]);
}

- (void)testIsKnownHost_whenADTrustedAuthorityChina_shuldReturnTrue
{
    XCTAssertTrue([ADALAuthorityUtils isKnownHost:[NSURL URLWithString:@"https://login.chinacloudapi.cn"]]);
}

- (void)testIsKnownHost_whenADTrustedAuthorityGermany_shuldReturnTrue
{
    XCTAssertTrue([ADALAuthorityUtils isKnownHost:[NSURL URLWithString:@"https://login.microsoftonline.de"]]);
}

- (void)testIsKnownHost_whenADTrustedAuthorityWorldWide_shuldReturnTrue
{
    XCTAssertTrue([ADALAuthorityUtils isKnownHost:[NSURL URLWithString:@"https://login.microsoftonline.com"]]);
}

- (void)testIsKnownHost_whenADTrustedAuthorityUSGovernment_shuldReturnTrue
{
    XCTAssertTrue([ADALAuthorityUtils isKnownHost:[NSURL URLWithString:@"https://login-us.microsoftonline.com"]]);
}

- (void)testIsKnownHost_whenADTrustedAuthorityCloudGovApi_shuldReturnTrue
{
    XCTAssertTrue([ADALAuthorityUtils isKnownHost:[NSURL URLWithString:@"https://login.cloudgovapi.us"]]);
}

- (void)testIsKnownHost_whenInvalid_shouldReturnFalse
{
    XCTAssertFalse([ADALAuthorityUtils isKnownHost:[NSURL URLWithString:@"https://www.noknownhost.com"]]);
}

@end
