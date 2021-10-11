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
#import "XCTestCase+TestHelperMethods.h"
#import "ADALAuthenticationContext.h"
#import "ADALTokenCacheItem+Internal.h"
#import "ADALUserInformation.h"

@interface ADALTokenCacheItemTests : ADTestCase

@end

@implementation ADALTokenCacheItemTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

#pragma mark - expiresOn

// TODO: There is a dependency of ADALTokenCacheItem on [[ADALAuthenticationSettings sharedInstance] expirationBuffer].
// It breaks "The Dependency Inversion Principle".
// Fix this dependency and change tests accordingly.

- (void)testIsExpired_whenExpiresOnIsNow_shouldReturnTrue
{
    ADALTokenCacheItem *item = [self adCreateCacheItem:@"eric@contoso.com"];
    item.expiresOn = [NSDate new];
    XCTAssertTrue(item.isExpired, "When time is now, the item should expire.");
}

- (void)testIsExpired_whenExpiresOnIs30sFromNow_shoudReturnTrue
{
    ADALTokenCacheItem *item = [self adCreateCacheItem:@"eric@contoso.com"];
    item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:30];
    
    XCTAssertTrue(item.isExpired, "The device clock can be off by a minute, so we should have enough buffer.");
}

- (void)testIsExpired_whenExpiresOnIsNil_shoudReturnFalse
{
    ADALTokenCacheItem *item = [self adCreateCacheItem:@"eric@contoso.com"];
    item.expiresOn = nil;
    
    XCTAssertFalse(item.isExpired, "No expiration time.");
}

- (void)testIsExpired_whenExpiresOnIsDistantFuture_shoudReturnFalse
{
    ADALTokenCacheItem *item = [self adCreateCacheItem:@"eric@contoso.com"];
    item.expiresOn = [NSDate distantFuture];
    
    XCTAssertFalse(item.isExpired);
}

- (void)testIsExpired_whenExpiresOnIsDistantPast_shoudReturnTrue
{
    ADALTokenCacheItem *item = [self adCreateCacheItem:@"eric@contoso.com"];
    item.expiresOn = [NSDate distantPast];
    
    XCTAssertTrue(item.isExpired);
}

- (void)testIsExpired_whenExpiresOnIsOneHourFromNow_shoudReturnFalse
{
    ADALTokenCacheItem *item = [self adCreateCacheItem:@"eric@contoso.com"];
    item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:3600];
    
    XCTAssertFalse(item.isExpired);
}

#pragma mark - isEmptyUser

- (void)testIsEmptyUser_whenUserInformationIsValid_shouldReturnFalse
{
    ADALTokenCacheItem *item = [self adCreateCacheItem:@"eric@contoso.com"];
    
    XCTAssertFalse(item.isEmptyUser);
}

- (void)testIsEmptyUser_whenUserInformationIsNil_shouldReturnTrue
{
    ADALTokenCacheItem *item = [self adCreateCacheItem:@"eric@contoso.com"];
    item.userInformation = nil;
    
    XCTAssertTrue(item.isEmptyUser);
}

#pragma mark - userInformation

- (void)testUserInformation_byDefault_shouldBeNil
{
    ADALTokenCacheItem *item = [ADALTokenCacheItem new];
    
    XCTAssertNil(item.userInformation);
}

#pragma mark - isMultiResourceRefreshToken

- (void)testIsMultiResourceRefreshToken_whenResourceValidAccessTokenValidRefreshTokenValid_shouldReturnFalse
{
    ADALTokenCacheItem *item = [ADALTokenCacheItem new];
    item.resource = TEST_RESOURCE;
    item.accessToken = TEST_ACCESS_TOKEN;
    item.refreshToken = TEST_REFRESH_TOKEN;
    
    XCTAssertFalse(item.isMultiResourceRefreshToken);
}

- (void)testIsMultiResourceRefreshToken_whenResourceNilAccessTokenValidRefreshTokenValid_shouldReturnFalse
{
    ADALTokenCacheItem *item = [ADALTokenCacheItem new];
    item.resource = nil;
    item.accessToken = TEST_ACCESS_TOKEN;
    item.refreshToken = TEST_REFRESH_TOKEN;
    
    XCTAssertFalse(item.isMultiResourceRefreshToken);
}

- (void)testIsMultiResourceRefreshToken_whenResourceNilAccessTokenNilRefreshTokenValid_shouldReturnTrue
{
    ADALTokenCacheItem *item = [ADALTokenCacheItem new];
    item.resource = nil;
    item.accessToken = nil;
    item.refreshToken = TEST_REFRESH_TOKEN;
    
    XCTAssertTrue(item.isMultiResourceRefreshToken);
}

- (void)testIsMultiResourceRefreshToken_whenResourceNilAccessTokenNilRefreshTokenNil_shouldReturnFalse
{
    ADALTokenCacheItem *item = [ADALTokenCacheItem new];
    item.resource = nil;
    item.accessToken = nil;
    item.refreshToken = nil;
    
    XCTAssertFalse(item.isMultiResourceRefreshToken);
}

- (void)testIsMultiResourceRefreshToken_whenResourceNilAccessTokenNilRefreshTokenEmptyString_shouldReturnFalse
{
    ADALTokenCacheItem *item = [ADALTokenCacheItem new];
    item.resource = nil;
    item.accessToken = nil;
    item.refreshToken = @"  ";
    
    XCTAssertFalse(item.isMultiResourceRefreshToken);
}

#pragma mark - supportsSecureCoding

- (void)testSupportsSecureCoding_shouldReturnTrue
{
    XCTAssertTrue([ADALTokenCacheItem supportsSecureCoding], "Ensure that the unarchiving is secure.");
}

#pragma mark - copyWithZone

- (void)testCopyWithZone_whenAllPropertiesAreSet_shouldCopyAllOfThem
{
    ADALTokenCacheItem *item = [self createTestCacheItem];
    
    ADALTokenCacheItem *itemCopy = [item copyWithZone:nil];
    
    XCTAssertEqualObjects(item.resource, itemCopy.resource);
    XCTAssertEqualObjects(item.authority, itemCopy.authority);
    XCTAssertEqualObjects(item.clientId, itemCopy.clientId);
    XCTAssertEqualObjects(item.familyId, itemCopy.familyId);
    XCTAssertEqualObjects(item.accessToken, itemCopy.accessToken);
    XCTAssertEqualObjects(item.accessTokenType, itemCopy.accessTokenType);
    XCTAssertEqualObjects(item.refreshToken, itemCopy.refreshToken);
    XCTAssertEqualObjects(item.expiresOn, itemCopy.expiresOn);
    XCTAssertEqualObjects(item.userInformation, itemCopy.userInformation);
    XCTAssertEqualObjects(item.sessionKey, itemCopy.sessionKey);
    XCTAssertEqualObjects(item.additionalServer, itemCopy.additionalServer);
    XCTAssertEqualObjects(item, itemCopy);
    XCTAssertNotEqual([itemCopy hash], 0);
    XCTAssertEqual([item hash], [itemCopy hash]);
}

#pragma mark - isEqual

- (void)testIsEqual_whenAllPropertiesAreEqual_shouldReturnTrue
{
    ADALTokenCacheItem *lhs = [self createTestCacheItem];
    ADALTokenCacheItem *rhs = [self createTestCacheItem];
    
    XCTAssertEqualObjects(lhs, rhs);
}

- (void)testIsEqual_whenResourceIsNotEqual_shouldReturnFalse
{
    ADALTokenCacheItem *lhs = [ADALTokenCacheItem new];
    lhs.resource = @"qwe";
    ADALTokenCacheItem *rhs = [ADALTokenCacheItem new];
    rhs.resource = @"asd";
    
    XCTAssertNotEqualObjects(lhs, rhs);
}

- (void)testIsEqual_whenResourceIsEqual_shouldReturnTrue
{
    ADALTokenCacheItem *lhs = [ADALTokenCacheItem new];
    lhs.resource = TEST_RESOURCE;
    ADALTokenCacheItem *rhs = [ADALTokenCacheItem new];
    rhs.resource = TEST_RESOURCE;
    
    XCTAssertEqualObjects(lhs, rhs);
}

- (void)testIsEqual_whenAuthorityIsNotEqual_shouldReturnFalse
{
    ADALTokenCacheItem *lhs = [ADALTokenCacheItem new];
    lhs.authority = @"qwe";
    ADALTokenCacheItem *rhs = [ADALTokenCacheItem new];
    rhs.authority = @"asd";
    
    XCTAssertNotEqualObjects(lhs, rhs);
}

- (void)testIsEqual_whenAuthorityIsEqual_shouldReturnTrue
{
    ADALTokenCacheItem *lhs = [ADALTokenCacheItem new];
    lhs.authority = TEST_AUTHORITY;
    ADALTokenCacheItem *rhs = [ADALTokenCacheItem new];
    rhs.authority = TEST_AUTHORITY;
    
    XCTAssertEqualObjects(lhs, rhs);
}

- (void)testIsEqual_whenClientIdIsNotEqual_shouldReturnFalse
{
    ADALTokenCacheItem *lhs = [ADALTokenCacheItem new];
    lhs.clientId = @"qwe";
    ADALTokenCacheItem *rhs = [ADALTokenCacheItem new];
    rhs.clientId = @"asd";
    
    XCTAssertNotEqualObjects(lhs, rhs);
}

- (void)testIsEqual_whenClientIdIsEqual_shouldReturnTrue
{
    ADALTokenCacheItem *lhs = [ADALTokenCacheItem new];
    lhs.clientId = TEST_CLIENT_ID;
    ADALTokenCacheItem *rhs = [ADALTokenCacheItem new];
    rhs.clientId = TEST_CLIENT_ID;
    
    XCTAssertEqualObjects(lhs, rhs);
}

- (void)testIsEqual_whenFamilyIdIsNotEqual_shouldReturnFalse
{
    ADALTokenCacheItem *lhs = [ADALTokenCacheItem new];
    lhs.familyId = @"qwe";
    ADALTokenCacheItem *rhs = [ADALTokenCacheItem new];
    rhs.familyId = @"asd";
    
    XCTAssertNotEqualObjects(lhs, rhs);
}

- (void)testIsEqual_whenFamilyIdIsEqual_shouldReturnTrue
{
    ADALTokenCacheItem *lhs = [ADALTokenCacheItem new];
    lhs.familyId = @"some family id";
    ADALTokenCacheItem *rhs = [ADALTokenCacheItem new];
    rhs.familyId = @"some family id";
    
    XCTAssertEqualObjects(lhs, rhs);
}

- (void)testIsEqual_whenAccessTokenIsNotEqual_shouldReturnFalse
{
    ADALTokenCacheItem *lhs = [ADALTokenCacheItem new];
    lhs.accessToken = @"qwe";
    ADALTokenCacheItem *rhs = [ADALTokenCacheItem new];
    rhs.accessToken = @"asd";
    
    XCTAssertNotEqualObjects(lhs, rhs);
}

- (void)testIsEqual_whenAccessTokenIsEqual_shouldReturnTrue
{
    ADALTokenCacheItem *lhs = [ADALTokenCacheItem new];
    lhs.accessToken = TEST_ACCESS_TOKEN;
    ADALTokenCacheItem *rhs = [ADALTokenCacheItem new];
    rhs.accessToken = TEST_ACCESS_TOKEN;
    
    XCTAssertEqualObjects(lhs, rhs);
}

- (void)testIsEqual_whenAccessTokenTypeIsNotEqual_shouldReturnFalse
{
    ADALTokenCacheItem *lhs = [ADALTokenCacheItem new];
    lhs.accessTokenType = @"qwe";
    ADALTokenCacheItem *rhs = [ADALTokenCacheItem new];
    rhs.accessTokenType = @"asd";
    
    XCTAssertNotEqualObjects(lhs, rhs);
}

- (void)testIsEqual_whenAccessTokenTypeIsEqual_shouldReturnTrue
{
    ADALTokenCacheItem *lhs = [ADALTokenCacheItem new];
    lhs.accessTokenType = TEST_ACCESS_TOKEN_TYPE;
    ADALTokenCacheItem *rhs = [ADALTokenCacheItem new];
    rhs.accessTokenType = TEST_ACCESS_TOKEN_TYPE;
    
    XCTAssertEqualObjects(lhs, rhs);
}

- (void)testIsEqual_whenRefreshTokenIsNotEqual_shouldReturnFalse
{
    ADALTokenCacheItem *lhs = [ADALTokenCacheItem new];
    lhs.refreshToken = @"qwe";
    ADALTokenCacheItem *rhs = [ADALTokenCacheItem new];
    rhs.refreshToken = @"asd";
    
    XCTAssertNotEqualObjects(lhs, rhs);
}

- (void)testIsEqual_whenRefreshTokenIsEqual_shouldReturnTrue
{
    ADALTokenCacheItem *lhs = [ADALTokenCacheItem new];
    lhs.refreshToken = TEST_REFRESH_TOKEN;
    ADALTokenCacheItem *rhs = [ADALTokenCacheItem new];
    rhs.refreshToken = TEST_REFRESH_TOKEN;
    
    XCTAssertEqualObjects(lhs, rhs);
}

- (void)testIsEqual_whenExpiresOnIsNotEqual_shouldReturnFalse
{
    ADALTokenCacheItem *lhs = [ADALTokenCacheItem new];
    lhs.expiresOn = [NSDate dateWithTimeIntervalSince1970:1500000000];
    ADALTokenCacheItem *rhs = [ADALTokenCacheItem new];
    rhs.expiresOn = [NSDate dateWithTimeIntervalSince1970:1900000000];
    
    XCTAssertNotEqualObjects(lhs, rhs);
}

- (void)testIsEqual_whenExpiresOnIsEqual_shouldReturnTrue
{
    ADALTokenCacheItem *lhs = [ADALTokenCacheItem new];
    lhs.expiresOn = [NSDate dateWithTimeIntervalSince1970:1500000000];
    ADALTokenCacheItem *rhs = [ADALTokenCacheItem new];
    rhs.expiresOn = [NSDate dateWithTimeIntervalSince1970:1500000000];
    
    XCTAssertEqualObjects(lhs, rhs);
}

- (void)testIsEqual_whenUserInformationIsNotEqual_shouldReturnFalse
{
    ADALTokenCacheItem *lhs = [ADALTokenCacheItem new];
    lhs.userInformation = [self adCreateUserInformation:TEST_USER_ID];
    [lhs.userInformation setValue:@"qwe" forKey:@"rawIdToken"];
    ADALTokenCacheItem *rhs = [ADALTokenCacheItem new];
    rhs.userInformation = [self adCreateUserInformation:TEST_USER_ID];
    [rhs.userInformation setValue:@"asd" forKey:@"rawIdToken"];
    
    XCTAssertNotEqualObjects(lhs, rhs);
}

- (void)testIsEqual_whenUserInformationIsEqual_shouldReturnTrue
{
    ADALTokenCacheItem *lhs = [ADALTokenCacheItem new];
    lhs.userInformation = [self adCreateUserInformation:TEST_USER_ID];
    ADALTokenCacheItem *rhs = [ADALTokenCacheItem new];
    rhs.userInformation = [self adCreateUserInformation:TEST_USER_ID];
    
    XCTAssertEqualObjects(lhs, rhs);
}

- (void)testIsEqual_whenSessionKeyIsNotEqual_shouldReturnFalse
{
    ADALTokenCacheItem *lhs = [ADALTokenCacheItem new];
    lhs.sessionKey = [@"qwe" dataUsingEncoding:NSUTF8StringEncoding];
    ADALTokenCacheItem *rhs = [ADALTokenCacheItem new];
    rhs.sessionKey = [@"asd" dataUsingEncoding:NSUTF8StringEncoding];
    
    XCTAssertNotEqualObjects(lhs, rhs);
}

- (void)testIsEqual_whenSessionKeyIstEqual_shouldReturnTrue
{
    ADALTokenCacheItem *lhs = [ADALTokenCacheItem new];
    lhs.sessionKey = [@"session key" dataUsingEncoding:NSUTF8StringEncoding];
    ADALTokenCacheItem *rhs = [ADALTokenCacheItem new];
    rhs.sessionKey = [@"session key" dataUsingEncoding:NSUTF8StringEncoding];
    
    XCTAssertEqualObjects(lhs, rhs);
}

- (void)testIsEqual_whenAdditionalServerIsNotEqual_shouldReturnFalse
{
    ADALTokenCacheItem *lhs = [ADALTokenCacheItem new];
    [lhs setValue:@{@"k1":@"v1"} forKey:@"additionalServer"];
    ADALTokenCacheItem *rhs = [ADALTokenCacheItem new];
    [rhs setValue:@{@"k2":@"v2"} forKey:@"additionalServer"];
    
    XCTAssertNotEqualObjects(lhs, rhs);
}

- (void)testIsEqual_whenAdditionalServerIsEqual_shouldReturnTrue
{
    ADALTokenCacheItem *lhs = [ADALTokenCacheItem new];
    [lhs setValue:@{@"k1":@"v1"} forKey:@"additionalServer"];
    ADALTokenCacheItem *rhs = [ADALTokenCacheItem new];
    [rhs setValue:@{@"k1":@"v1"} forKey:@"additionalServer"];
    
    XCTAssertEqualObjects(lhs, rhs);
}

#pragma mark - 
- (void)testV1BackCompatData
{
    NSString* base64String = @"YnBsaXN0MDDUAQIDBAUGhodYJHZlcnNpb25YJG9iamVjdHNZJGFyY2hpdmVyVCR0b3ASAAGGoK8QKwcIGxwdHh8gJCo0OD0+YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6foJVJG51bGzZCQoLDA0ODxAREhMUFRYXGBkaViRjbGFzc1lhdXRob3JpdHlYcmVzb3VyY2VfEA91c2VySW5mb3JtYXRpb25ZZXhwaXJlc09uWGNsaWVudElkXHJlZnJlc2hUb2tlblthY2Nlc3NUb2tlbl8QD2FjY2Vzc1Rva2VuVHlwZYAqgAKAAIAJgAeAA4AGgASABV8QKGh0dHBzOi8vbG9naW4ubWljcm9zb2Z0b25saW5lLmNvbS9jb21tb25fECQyN0FEODNDOS1GQzA1LTRBNkMtQUYwMS0zNkVEQTQyRUQxOEZePGFjY2VzcyB0b2tlbj5WQmVhcmVyXxAPPHJlZnJlc2ggdG9rZW4+0iEJIiNXTlMudGltZSNBLoSAAAAAAIAI0iUmJyhaJGNsYXNzbmFtZVgkY2xhc3Nlc1ZOU0RhdGWiJylYTlNPYmplY3TVKywtLgkvMDEyM18QEXVzZXJJZERpc3BsYXlhYmxlWWFsbENsYWltc1pyYXdJZFRva2VuVnVzZXJJZAmADYAMgAqAKdIJNTY3WU5TLnN0cmluZ4ALXxAWbXlmYWtldXNlckBjb250b3NvLmNvbdIlJjk6XxAPTlNNdXRhYmxlU3RyaW5nozs8KV8QD05TTXV0YWJsZVN0cmluZ1hOU1N0cmluZ18RAlBleUowZVhBaU9pSktWMVFpTENKaGRXUWlPaUpqTTJNM1pqVmxOUzAzTVRVekxUUTBaRFF0T1RCbE5pMHpNamsyT0Raa05EaGtOellpTENKcGMzTWlPaUpvZEhSd2N6b3ZMM04wY3k1M2FXNWtiM2R6TG01bGRDODJabVF4WmpWalpDMWhPVFJqTFRRek16VXRPRGc1WWkwMll6VTVPR1UyWkRnd05EZ3ZJaXdpYVdGMElqb3hNemczTWpJME1UWTVMQ0p1WW1ZaU9qRXpPRGN5TWpReE5qa3NJbVY0Y0NJNk1UTTROekl5TnpjMk9Td2lkbVZ5SWpvaU1TNHdJaXdpZEdsa0lqb2lObVprTVdZMVkyUXRZVGswWXkwME16TTFMVGc0T1dJdE5tTTFPVGhsTm1RNE1EUTRJaXdpYjJsa0lqb2lOVE5qTm1GalpqSXRNamMwTWkwME5UTTRMVGt4T0dRdFpUYzRNalUzWldNNE5URTJJaXdpZFhCdUlqb2liWGxtWVd0bGRYTmxja0JqYjI1MGIzTnZMbU52YlNJc0luVnVhWEYxWlY5dVlXMWxJam9pYlhsbVlXdGxkWE5sY2tCamIyNTBiM052TG1OdmJTSXNJbk4xWWlJNklqQkVlRzVCYkV4cE1USkpka2RNWDJSSE0yUkVUV3N6ZW5BMlFWRklibXBuYjJkNWFXMDFRVmR3VTJNaUxDSm1ZVzFwYkhsZmJtRnRaU0k2SWxWelpYSWlMQ0puYVhabGJsOXVZVzFsSWpvaVJtRnJaU0o50z9ACUFQX1dOUy5rZXlzWk5TLm9iamVjdHOuQkNERUZHSElKS0xNTk+ADoAPgBCAEYASgBOAFIAVgBaAF4AYgBmAGoAbrlFSU1RVVldYUlpbXFFegByAHYAegB+AIIAhgCKAI4AdgCSAJYAmgByAJ4AoU3VwblNuYmZTZXhwU2lzc1NvaWRTdHlwU3ZlclNhdWRTaWF0W2ZhbWlseV9uYW1lU3N1YlN0aWRbdW5pcXVlX25hbWVaZ2l2ZW5fbmFtZV8QFm15ZmFrZXVzZXJAY29udG9zby5jb20SUq9caRJSr2p5XxA9aHR0cHM6Ly9zdHMud2luZG93cy5uZXQvNmZkMWY1Y2QtYTk0Yy00MzM1LTg4OWItNmM1OThlNmQ4MDQ4L18QJDUzYzZhY2YyLTI3NDItNDUzOC05MThkLWU3ODI1N2VjODUxNlNKV1RTMS4wXxAkYzNjN2Y1ZTUtNzE1My00NGQ0LTkwZTYtMzI5Njg2ZDQ4ZDc2VFVzZXJfECswRHhuQWxMaTEySXZHTF9kRzNkRE1rM3pwNkFRSG5qZ29neWltNUFXcFNjXxAkNmZkMWY1Y2QtYTk0Yy00MzM1LTg4OWItNmM1OThlNmQ4MDQ4VEZha2XSJSZ7fFxOU0RpY3Rpb25hcnmifSlcTlNEaWN0aW9uYXJ50iUmf4BfEBFBRFVzZXJJbmZvcm1hdGlvbqKBKV8QEUFEVXNlckluZm9ybWF0aW9u0iUmg4RfEBVBRFRva2VuQ2FjaGVTdG9yZUl0ZW2ihSlfEBVBRFRva2VuQ2FjaGVTdG9yZUl0ZW1fEA9OU0tleWVkQXJjaGl2ZXLRiIlUcm9vdIABAAgAEQAaACMALQAyADcAZQBrAH4AhQCPAJgAqgC0AL0AygDWAOgA6gDsAO4A8ADyAPQA9gD4APoBJQFMAVsBYgF0AXkBgQGKAYwBkQGcAaUBrAGvAbgBwwHXAeEB7AHzAfQB9gH4AfoB/AIBAgsCDQImAisCPQJBAlMCXASwBLcEvwTKBNkE2wTdBN8E4QTjBOUE5wTpBOsE7QTvBPEE8wT1BQQFBgUIBQoFDAUOBRAFEgUUBRYFGAUaBRwFHgUgBSIFJgUqBS4FMgU2BToFPgVCBUYFUgVWBVoFZgVxBYoFjwWUBdQF+wX/BgMGKgYvBl0GhAaJBo4GmwaeBqsGsAbEBscG2wbgBvgG+wcTByUHKActAAAAAAAAAgEAAAAAAAAAigAAAAAAAAAAAAAAAAAABy8=";
    
    NSData* itemData = [[NSData alloc] initWithBase64EncodedString:base64String options:0];
    XCTAssertNotNil(itemData);
    ADALTokenCacheItem* item = nil;
    if (@available(macOS 10.13, iOS 12.0, *)) {
        item = [NSKeyedUnarchiver unarchivedObjectOfClass:ADALTokenCacheItem.class fromData:itemData error:nil];
    } else {
        // Fallback on earlier versions
        item = [NSKeyedUnarchiver unarchiveObjectWithData:itemData];
    }
    XCTAssertNotNil(item);
    
    XCTAssertEqualObjects(item.authority, @"https://login.microsoftonline.com/common");
    XCTAssertEqualObjects(item.accessToken, @"<access token>");
    XCTAssertEqualObjects(item.accessTokenType, @"Bearer");
    XCTAssertEqualObjects(item.refreshToken, @"<refresh token>");
    XCTAssertEqualObjects(item.clientId, @"27AD83C9-FC05-4A6C-AF01-36EDA42ED18F");
    XCTAssertEqualObjects(item.expiresOn, [NSDate dateWithTimeIntervalSinceReferenceDate:1000000]);
    XCTAssertEqualObjects(item.userInformation.userId, @"myfakeuser@contoso.com");
    
    NSString* originalIdToken = @"eyJ0eXAiOiJKV1QiLCJhdWQiOiJjM2M3ZjVlNS03MTUzLTQ0ZDQtOTBlNi0zMjk2ODZkNDhkNzYiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC82ZmQxZjVjZC1hOTRjLTQzMzUtODg5Yi02YzU5OGU2ZDgwNDgvIiwiaWF0IjoxMzg3MjI0MTY5LCJuYmYiOjEzODcyMjQxNjksImV4cCI6MTM4NzIyNzc2OSwidmVyIjoiMS4wIiwidGlkIjoiNmZkMWY1Y2QtYTk0Yy00MzM1LTg4OWItNmM1OThlNmQ4MDQ4Iiwib2lkIjoiNTNjNmFjZjItMjc0Mi00NTM4LTkxOGQtZTc4MjU3ZWM4NTE2IiwidXBuIjoibXlmYWtldXNlckBjb250b3NvLmNvbSIsInVuaXF1ZV9uYW1lIjoibXlmYWtldXNlckBjb250b3NvLmNvbSIsInN1YiI6IjBEeG5BbExpMTJJdkdMX2RHM2RETWszenA2QVFIbmpnb2d5aW01QVdwU2MiLCJmYW1pbHlfbmFtZSI6IlVzZXIiLCJnaXZlbl9uYW1lIjoiRmFrZSJ9";
    XCTAssertEqualObjects(item.userInformation.rawIdToken, originalIdToken);
    
}

// Round trip the item though NSKeyedArchiver and NSKeyedUnarchiver to ensure the initWithCoder: and
// encodeWithCoder: are properly implemented.
- (void)testCoder
{
    ADALTokenCacheItem* item = [self adCreateATCacheItem];
    XCTAssertNotNil(item);
    XCTAssertNotEqual([item hash], 0);
    NSData* data = nil;
    ADALTokenCacheItem* unarchivedItem;
    if (@available(macOS 10.13, iOS 12.0, *)) {
        data = [NSKeyedArchiver archivedDataWithRootObject:item requiringSecureCoding:YES error:nil];
        XCTAssertNotNil(data);
        unarchivedItem= [NSKeyedUnarchiver unarchivedObjectOfClass:[ADALTokenCacheItem class] fromData:data error:nil];
    } else {
        // Fallback on earlier versions
        data = [NSKeyedUnarchiver unarchiveObjectWithData:data];
    }
    XCTAssertNotNil(unarchivedItem);
    
    XCTAssertEqualObjects(item, unarchivedItem);
    XCTAssertEqual([item hash], [unarchivedItem hash]);
}

#pragma mark - Private

- (ADALTokenCacheItem *)createTestCacheItem
{
    ADALTokenCacheItem *item = [ADALTokenCacheItem new];
    item.resource = TEST_RESOURCE;
    item.authority = TEST_AUTHORITY;
    item.clientId = TEST_CLIENT_ID;
    item.familyId = @"some family id";
    item.accessToken = TEST_ACCESS_TOKEN;
    item.accessTokenType = TEST_ACCESS_TOKEN_TYPE;
    item.refreshToken = TEST_REFRESH_TOKEN;
    item.expiresOn = [NSDate dateWithTimeIntervalSince1970:1500000000];
    item.userInformation = [self adCreateUserInformation:TEST_USER_ID];
    item.sessionKey = [@"session key" dataUsingEncoding:NSUTF8StringEncoding];
    [item setValue:@{@"some key": @"some value"} forKey:@"additionalServer"];
    
    return item;
}

@end
