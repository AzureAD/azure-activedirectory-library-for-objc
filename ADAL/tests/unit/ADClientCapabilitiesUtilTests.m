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
#import "ADClientCapabilitiesUtil.h"

@interface ADClientCapabilitiesUtilTests : XCTestCase

@end

@implementation ADClientCapabilitiesUtilTests

#pragma mark - claimsParameterFromCapabilities

- (void)testclaimsParameterFromCapabilities_whenNilCapabilities_shouldReturnNil
{
    NSArray *inputCapabilities = nil;

    NSString *result = [ADClientCapabilitiesUtil claimsParameterFromCapabilities:inputCapabilities];

    XCTAssertNil(result);
}

- (void)testclaimsParameterFromCapabilities_whenEmptyCapabilities_shouldReturnNil
{
    NSArray *inputCapabilities = @[];

    NSString *result = [ADClientCapabilitiesUtil claimsParameterFromCapabilities:inputCapabilities];

    XCTAssertNil(result);
}

- (void)testclaimsParameterFromCapabilities_whenKnownCapabilities_shouldReturnClaimsJSON
{
    NSArray *inputCapabilities = @[@"llt"];

    NSString *result = [ADClientCapabilitiesUtil claimsParameterFromCapabilities:inputCapabilities];

    XCTAssertNotNil(result);
    XCTAssertEqualObjects(result, @"{\"access_token\":{\"xms_cc\":{\"values\":[\"llt\"]}}}");
}

- (void)testclaimsParameterFromCapabilities_whenMultipleCapabilities_shouldReturnClaimsJSONWithAllCapabilities
{
    NSArray *inputCapabilities = @[@"unknown1", @"llt", @"unknown2"];

    NSString *result = [ADClientCapabilitiesUtil claimsParameterFromCapabilities:inputCapabilities];

    XCTAssertNotNil(result);
    XCTAssertEqualObjects(result, @"{\"access_token\":{\"xms_cc\":{\"values\":[\"unknown1\",\"llt\",\"unknown2\"]}}}");
}

#pragma mark - claimsParameterFromCapabilities:developerClaims:

- (void)testclaimsParameterFromCapabilitiesAndDeveloperClaims_whenNilCapabilities_andNilDeveloperClaims_shouldReturnNil
{
    NSArray *inputCapabilities = nil;
    NSDictionary *inputClaims = nil;

    NSString *result = [ADClientCapabilitiesUtil claimsParameterFromCapabilities:inputCapabilities developerClaims:inputClaims];

    XCTAssertNil(result);
}

- (void)testclaimsParameterFromCapabilitiesAndDeveloperClaims_whenNilCapabilities_andNonNilDeveloperClaims_shouldReturnDeveloperClaims
{
    NSArray *inputCapabilities = nil;
    NSDictionary *inputClaims = @{@"access_token":@{@"polids":@{@"essential":@YES,@"values":@[@"d77e91f0-fc60-45e4-97b8-14a1337faa28"]}}};

    NSString *result = [ADClientCapabilitiesUtil claimsParameterFromCapabilities:inputCapabilities developerClaims:inputClaims];

    XCTAssertNotNil(result);

    NSString *expectedResult = @"{\"access_token\":{\"polids\":{\"values\":[\"d77e91f0-fc60-45e4-97b8-14a1337faa28\"],\"essential\":true}}}";
    XCTAssertEqualObjects(result, expectedResult);
}

- (void)testclaimsParameterFromCapabilitiesAndDeveloperClaims_whenNonNilCapabilities_andNilDeveloperClaims_shouldReturnCapabilitiesClaims
{
    NSArray *inputCapabilities = @[@"llt"];
    NSDictionary *inputClaims = nil;

    NSString *result = [ADClientCapabilitiesUtil claimsParameterFromCapabilities:inputCapabilities developerClaims:inputClaims];

    XCTAssertNotNil(result);

    NSString *expectedResult = @"{\"access_token\":{\"xms_cc\":{\"values\":[\"llt\"]}}}";
    XCTAssertEqualObjects(result, expectedResult);
}

- (void)testclaimsParameterFromCapabilitiesAndDeveloperClaims_whenNonNilCapabilities_andNonNilDeveloperClaims_shouldReturnBoth
{
    NSArray *inputCapabilities = @[@"llt"];
    NSDictionary *inputClaims = @{@"id_token":@{@"polids":@{@"essential":@YES,@"values":@[@"d77e91f0-fc60-45e4-97b8-14a1337faa28"]}}};;

    NSString *result = [ADClientCapabilitiesUtil claimsParameterFromCapabilities:inputCapabilities developerClaims:inputClaims];

    XCTAssertNotNil(result);

    NSString *expectedResult = @"{\"access_token\":{\"xms_cc\":{\"values\":[\"llt\"]}},\"id_token\":{\"polids\":{\"values\":[\"d77e91f0-fc60-45e4-97b8-14a1337faa28\"],\"essential\":true}}}";
    XCTAssertEqualObjects(result, expectedResult);
}

- (void)testclaimsParameterFromCapabilitiesAndDeveloperClaims_whenNonNilCapabilities_andNonNilDeveloperClaims_andAccessTokenClaimsInBoth_shouldMergeClaims
{
     NSArray *inputCapabilities = @[@"cp1", @"llt"];
     NSDictionary *inputClaims = @{@"access_token":@{@"polids":@{@"essential":@YES,@"values":@[@"d77e91f0-fc60-45e4-97b8-14a1337faa28"]}}};

    NSString *result = [ADClientCapabilitiesUtil claimsParameterFromCapabilities:inputCapabilities developerClaims:inputClaims];

    XCTAssertNotNil(result);

    NSString *expectedResult = @"{\"access_token\":{\"polids\":{\"values\":[\"d77e91f0-fc60-45e4-97b8-14a1337faa28\"],\"essential\":true},\"xms_cc\":{\"values\":[\"cp1\",\"llt\"]}}}";
    XCTAssertEqualObjects(result, expectedResult);
}


@end
