// Copyright © Microsoft Open Technologies, Inc.
//
// All Rights Reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
// ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
// PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
//
// See the Apache License, Version 2.0 for the specific language
// governing permissions and limitations under the License.

#import <XCTest/XCTest.h>
#import "XCTestCase+TestHelperMethods.h"
#import <ADALiOS/ADProfileInfo.h>
#import "ADTestUtils.h"

@interface ADProfileInfoTests : XCTestCase

@end

@implementation ADProfileInfoTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

- (void)testInitFailures
{
    ADAuthenticationError* error;
    ADProfileInfo* userInfo = [ADProfileInfo profileInfoWithUsername:nil error:&error];
    [self adValidateFactoryForInvalidArgument:@"userId" returnedObject:userInfo error:error];

    error = nil;//Clear before next execution
    userInfo = [ADProfileInfo profileInfoWithUsername:@"" error:&error];
    [self adValidateFactoryForInvalidArgument:@"userId" returnedObject:userInfo error:error];

    error = nil;//Clear before next execution:
    userInfo = [ADProfileInfo profileInfoWithUsername:@"  " error:&error];
    [self adValidateFactoryForInvalidArgument:@"userId" returnedObject:userInfo error:error];

    error = nil;
    userInfo = [ADProfileInfo profileInfoWithUsername:@"valid user" error:&error];
    XCTAssertNotNil(userInfo);
    ADAssertNoError;
}

- (void)testDefaultCreation
{
    NSString* errorDetails = nil;
    ADProfileInfo* profileInfo = [[ADTestUtils defaultUtils] createProfileInfo:&errorDetails];
    XCTAssertNotNil(profileInfo, @"Failed to create profile info: %@", errorDetails);
}

// Verify that -isEqual is properly testing all the properties in the object
- (void)testIsEqual
{
    NSString* errorDetails = nil;
    ADTestUtils* utils = [ADTestUtils defaultUtils];
    
    // Create two identical profile info objects
    ADProfileInfo* profileInfo = [utils createProfileInfo:&errorDetails];
    XCTAssertNotNil(profileInfo, @"Failed to create profile info: %@", errorDetails);
    ADProfileInfo* profileInfo2 = [utils createProfileInfo:&errorDetails];
    XCTAssertNotNil(profileInfo2, @"Failed to create profile info: %@", errorDetails);
    
    // Verify all of the properies in them are the same
    XCTAssertEqualObjects(profileInfo.username, profileInfo2.username);
    XCTAssertEqualObjects(profileInfo.friendlyName, profileInfo2.friendlyName);
    XCTAssertEqualObjects(profileInfo.subject, profileInfo2.subject);
    XCTAssertEqualObjects(profileInfo.rawProfileInfo, profileInfo2.rawProfileInfo);
    XCTAssertEqualObjects(profileInfo.allClaims, profileInfo2.allClaims);
    
    // Verify -isEqual says the objects are the same
    XCTAssertEqualObjects(profileInfo, profileInfo2);
}

- (void)testCopy
{
    NSString* errorDetails = nil;
    ADProfileInfo* profileInfo = [[ADTestUtils defaultUtils] createProfileInfo:&errorDetails];
    XCTAssertNotNil(profileInfo, @"Failed to create profile info: %@", errorDetails);
    
    ADProfileInfo* copy = [profileInfo copy];
    XCTAssertNotNil(copy);
    XCTAssertEqualObjects(copy, profileInfo);
}

- (void)testIdTokenBad
{
    ADAuthenticationError* error = nil;
    ADProfileInfo* userInfo = [ADProfileInfo profileInfoWithEncodedString:@"" error:&error];
    XCTAssertNotNil(error);
    XCTAssertNil(userInfo);
    
    error = nil;
    userInfo = [ADProfileInfo profileInfoWithEncodedString:nil error:&error];
    XCTAssertNotNil(error);
    XCTAssertNil(userInfo);
    
    error = nil;
    userInfo = [ADProfileInfo profileInfoWithEncodedString:@"....." error:&error];
    XCTAssertNotNil(error);
    XCTAssertNil(userInfo);

    //Pass nil for error:
    userInfo = [ADProfileInfo profileInfoWithEncodedString:@"....." error:nil];
    XCTAssertNil(userInfo);

    error = nil;
    NSString* plain = @"{\"aud\":\"c3c7f5e5-7153-44d4-90e6-329686d48d76\",\"iss\":\"https://sts.windows.net/6fd1f5cd-a94c-4335-889b-6c598e6d8048/\",\"iat\":1387224169,\"nbf\":1387224169,\"exp\":1387227769,\"ver\":\"1.0\",\"tid\":\"6fd1f5cd-a94c-4335-889b-6c598e6d8048\",\"oid\":\"53c6acf2-2742-4538-918d-e78257ec8516\",\"upn\":\"boris@MSOpenTechBV.onmicrosoft.com\",\"unique_name\":\"boris@MSOpenTechBV.onmicrosoft.com\",\"sub\":\"0DxnAlLi12IvGL_dG3dDMk3zp6AQHnjgogyim5AWpSc\",\"family_name\":\"Vidolovv\",\"given_name\":\"Boriss\"}";
    userInfo = [ADProfileInfo profileInfoWithEncodedString:plain error:&error];
    XCTAssertNotNil(error);
    XCTAssertNil(userInfo);
    
    error = nil;
    NSString* plainNoUserId = @"{\"aud\":\"c3c7f5e5-7153-44d4-90e6-329686d48d76\",\"iss\":\"https://sts.windows.net/6fd1f5cd-a94c-4335-889b-6c598e6d8048/\",\"iat\":1387224169,\"nbf\":1387224169,\"exp\":1387227769,\"ver\":\"1.0\",\"tid\":\"6fd1f5cd-a94c-4335-889b-6c598e6d8048\",\"family_name\":\"Vidolovv\",\"given_name\":\"Boriss\"}";//Missing meaningful userID field
    NSString* encoded = [plainNoUserId adBase64UrlEncode];
    userInfo = [ADProfileInfo profileInfoWithEncodedString:encoded error:&error];
    XCTAssertNotNil(error);
    XCTAssertNil(userInfo);
    
    
    error = nil;
    NSString* badJSON = @"{\"aud\":\"c3c7f5e5-7153-44d4-90e6-329686d48d76\",\"iss\":\"https://sts.windows.net/6fd1f5cd-a94c-4335-889b-6c598e6d8048/\",\"iat\":1387224169,\"nbf\":1387224169,\"exp\":1387227769,\"ver\":\"1.0\",\"tid\":\"6fd1f5cd-a94c-4335-889b-6c598e6d8048\",\"oid\":\"53c6acf2-2742-4538-918d-e78257ec8516\",\"upn\":\"boris@MSOpenTechBV.onmicrosoft.com\",\"unique_name\":\"boris@MSOpenTechBV.onmicrosoft.com\",\"sub\":\"0DxnAlLi12IvGL_dG3dDMk3zp6AQHnjgogyim5AWpSc\",\"family_name\":\"Vidolovv\",\"given_name\":\"Boriss\"";//Missing closing braket '}'
    encoded = [badJSON adBase64UrlEncode];
    userInfo = [ADProfileInfo profileInfoWithEncodedString:encoded error:&error];
    XCTAssertNotNil(error);
    XCTAssertNil(userInfo);
}

- (void)testSupportSecureCoding
{
    XCTAssertTrue([ADProfileInfo supportsSecureCoding], "Unarchiving should be secure.");
}

- (void)testArchivingRoundTrip
{
    // This object is encoded using NSKeyedArchiver so we need to make sure -initWithCoder: and encodeWithCoder:
    // are implemented correctly
    
    NSString* errorDetails = nil;
    ADProfileInfo* profileInfo = [[ADTestUtils defaultUtils] createProfileInfo:&errorDetails];
    XCTAssertNotNil(profileInfo, @"Failed to create profile info: %@", errorDetails);
    
    NSData* profileData = [NSKeyedArchiver archivedDataWithRootObject:profileInfo];
    XCTAssertNotNil(profileData);
    
    ADProfileInfo* unarchivedProfile = [NSKeyedUnarchiver unarchiveObjectWithData:profileData];
    XCTAssertNotNil(unarchivedProfile);
    
    XCTAssertEqualObjects(profileInfo, unarchivedProfile);
}

@end
