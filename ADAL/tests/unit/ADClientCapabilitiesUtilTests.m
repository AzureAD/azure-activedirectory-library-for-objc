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

#pragma mark - knownCapabilities

- (void)testKnownCapabilities_whenNilCapabilitiesPassed_shouldReturnNil
{
    NSArray *inputCapabilities = nil;

    NSArray *result = [ADClientCapabilitiesUtil knownCapabilities:inputCapabilities];

    XCTAssertNil(result);
}

- (void)testKnownCapabilities_whenNonStringCapabilitiesPassed_shouldReturnEmptyResult
{
    NSArray *inputCapabilities = @[[NSSet new]];

    NSArray *result = [ADClientCapabilitiesUtil knownCapabilities:inputCapabilities];

    XCTAssertEqualObjects(result, @[]);
}

- (void)testKnownCapabilities_whenNoKnownCapabilitiesPassed_shouldReturnEmptyResult
{
    NSArray *inputCapabilities = @[@"unknown"];

    NSArray *result = [ADClientCapabilitiesUtil knownCapabilities:inputCapabilities];

    XCTAssertNotNil(result);
    XCTAssertEqualObjects(result, @[]);
}

- (void)testKnownCapabilities_whenOnlyKnownCapabilitiesPassed_shouldReturnCapabilities
{
    NSArray *inputCapabilities = @[@"llt"];

    NSArray *result = [ADClientCapabilitiesUtil knownCapabilities:inputCapabilities];

    XCTAssertNotNil(result);
    XCTAssertEqualObjects(result, @[@"llt"]);
}

- (void)testKnownCapabilities_whenKnownAndUnknownCapabilitiesPassed_shouldReturnOnlyKnownCapabilities
{
    NSArray *inputCapabilities = @[@"unknown1", @"llt", @"unknown2"];

    NSArray *result = [ADClientCapabilitiesUtil knownCapabilities:inputCapabilities];

    XCTAssertNotNil(result);
    XCTAssertEqualObjects(result, @[@"llt"]);
}

#pragma mark - claimsRequestFromCapabilities

- (void)testClaimsRequestFromCapabilities_whenNilCapabilities_shouldReturnNil
{
    NSArray *inputCapabilities = nil;

    NSString *result = [ADClientCapabilitiesUtil claimsRequestFromCapabilities:inputCapabilities];

    XCTAssertNil(result);
}

- (void)testClaimsRequestFromCapabilities_whenEmptyCapabilities_shouldReturnNil
{
    NSArray *inputCapabilities = @[];

    NSString *result = [ADClientCapabilitiesUtil claimsRequestFromCapabilities:inputCapabilities];

    XCTAssertNil(result);
}

- (void)testClaimsRequestFromCapabilities_whenKnownCapabilities_shouldReturnClaimsJSON
{
    NSArray *inputCapabilities = @[@"llt"];

    NSString *result = [ADClientCapabilitiesUtil claimsRequestFromCapabilities:inputCapabilities];

    XCTAssertNotNil(result);
    XCTAssertEqualObjects(result, @"{\"access_token\":{\"xms_cc\":[\"llt\"]}}");
}

- (void)testClaimsRequestFromCapabilities_whenUnknowCapabilities_shouldReturnNil
{
    NSArray *inputCapabilities = @[@"unknown"];

    NSString *result = [ADClientCapabilitiesUtil claimsRequestFromCapabilities:inputCapabilities];

    XCTAssertNil(result);
}

- (void)testClaimsRequestFromCapabilities_whenKnownAndUnknownCapabilities_shouldReturnClaimsJSONWithKnownCapabilities
{
    NSArray *inputCapabilities = @[@"unknown1", @"llt", @"unknown2"];

    NSString *result = [ADClientCapabilitiesUtil claimsRequestFromCapabilities:inputCapabilities];

    XCTAssertNotNil(result);
    XCTAssertEqualObjects(result, @"{\"access_token\":{\"xms_cc\":[\"llt\"]}}");
}

#pragma mark - claimsRequestFromCapabilities:developerClaims:

- (void)testClaimsRequestFromCapabilitiesAndDeveloperClaims_whenNilCapabilities_andNilDeveloperClaims_shouldReturnNil
{
    NSArray *inputCapabilities = nil;
    NSDictionary *inputClaims = nil;

    NSString *result = [ADClientCapabilitiesUtil claimsRequestFromCapabilities:inputCapabilities developerClaims:inputClaims];

    XCTAssertNil(result);
}

- (void)testClaimsRequestFromCapabilitiesAndDeveloperClaims_whenNilCapabilities_andNonNilDeveloperClaims_shouldReturnDeveloperClaims
{
    NSArray *inputCapabilities = nil;
    NSDictionary *inputClaims = @{@"access_token":@{@"polids":@{@"essential":@YES,@"values":@[@"d77e91f0-fc60-45e4-97b8-14a1337faa28"]}}};

    NSString *result = [ADClientCapabilitiesUtil claimsRequestFromCapabilities:inputCapabilities developerClaims:inputClaims];

    XCTAssertNotNil(result);

    NSString *expectedResult = @"{\"access_token\":{\"polids\":{\"values\":[\"d77e91f0-fc60-45e4-97b8-14a1337faa28\"],\"essential\":true}}}";
    XCTAssertEqualObjects(result, expectedResult);
}

- (void)testClaimsRequestFromCapabilitiesAndDeveloperClaims_whenNonNilCapabilities_andNilDeveloperClaims_shouldReturnCapabilitiesClaims
{
    NSArray *inputCapabilities = @[@"llt"];
    NSDictionary *inputClaims = nil;

    NSString *result = [ADClientCapabilitiesUtil claimsRequestFromCapabilities:inputCapabilities developerClaims:inputClaims];

    XCTAssertNotNil(result);

    NSString *expectedResult = @"{\"access_token\":{\"xms_cc\":[\"llt\"]}}";
    XCTAssertEqualObjects(result, expectedResult);
}

- (void)testClaimsRequestFromCapabilitiesAndDeveloperClaims_whenNonNilCapabilities_andNonNilDeveloperClaims_shouldReturnBoth
{
    NSArray *inputCapabilities = @[@"llt"];
    NSDictionary *inputClaims = @{@"id_token":@{@"polids":@{@"essential":@YES,@"values":@[@"d77e91f0-fc60-45e4-97b8-14a1337faa28"]}}};;

    NSString *result = [ADClientCapabilitiesUtil claimsRequestFromCapabilities:inputCapabilities developerClaims:inputClaims];

    XCTAssertNotNil(result);

    NSString *expectedResult = @"{\"access_token\":{\"xms_cc\":[\"llt\"]},\"id_token\":{\"polids\":{\"values\":[\"d77e91f0-fc60-45e4-97b8-14a1337faa28\"],\"essential\":true}}}";
    XCTAssertEqualObjects(result, expectedResult);
}

- (void)testClaimsRequestFromCapabilitiesAndDeveloperClaims_whenNonNilCapabilities_andNonNilDeveloperClaims_andAccessTokenClaimsInBoth_shouldMergeClaims
{
     NSArray *inputCapabilities = @[@"unknown", @"llt", @"unknown2"];
     NSDictionary *inputClaims = @{@"access_token":@{@"polids":@{@"essential":@YES,@"values":@[@"d77e91f0-fc60-45e4-97b8-14a1337faa28"]}}};

    NSString *result = [ADClientCapabilitiesUtil claimsRequestFromCapabilities:inputCapabilities developerClaims:inputClaims];

    XCTAssertNotNil(result);

    NSString *expectedResult = @"{\"access_token\":{\"polids\":{\"values\":[\"d77e91f0-fc60-45e4-97b8-14a1337faa28\"],\"essential\":true},\"xms_cc\":[\"llt\"]}}";
    XCTAssertEqualObjects(result, expectedResult);
}


@end
