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
#import "ADTokenCacheItem+MSIDTokens.h"
#import "ADTokenCacheItem+Internal.h"
#import "XCTestCase+TestHelperMethods.h"
#import "ADUserInformation.h"
#import "MSIDLegacyAccessToken.h"
#import "MSIDLegacyRefreshToken.h"
#import "MSIDLegacySingleResourceToken.h"
#import "XCTestCase+TestHelperMethods.h"
#import "MSIDLegacyTokenCacheItem.h"

@interface ADTokenCacheItemIntegrationWithMSIDTokensTests : XCTestCase

@end

@implementation ADTokenCacheItemIntegrationWithMSIDTokensTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

#pragma mark - Tests

- (void)testInitWithAccessToken_shouldInitADTokenCacheItem
{
    MSIDLegacyAccessToken *accessToken = [self adCreateAccessToken];
    accessToken.storageAuthority = [NSURL URLWithString:@"https://login.authority2.com/common"];
    ADUserInformation *expectedInformation = [self adCreateUserInformation:TEST_USER_ID
                                                             homeAccountId:accessToken.clientInfo.accountIdentifier];

    ADTokenCacheItem *adToken = [[ADTokenCacheItem alloc] initWithLegacyAccessToken:accessToken];
    
    XCTAssertNotNil(adToken);
    XCTAssertEqualObjects(adToken.userInformation, expectedInformation);
    XCTAssertEqualObjects(adToken.expiresOn, [NSDate dateWithTimeIntervalSince1970:1500000000]);
    XCTAssertNil(adToken.sessionKey);
    XCTAssertNil(adToken.refreshToken);
    XCTAssertEqualObjects(adToken.accessTokenType, @"Bearer");
    XCTAssertEqualObjects(adToken.accessToken, @"access token");
    XCTAssertNil(adToken.familyId);
    XCTAssertEqualObjects(adToken.clientId, TEST_CLIENT_ID);
    XCTAssertEqualObjects(adToken.authority, TEST_AUTHORITY);
    XCTAssertEqualObjects(adToken.storageAuthority, @"https://login.authority2.com/common");
    XCTAssertEqualObjects(adToken.resource, TEST_RESOURCE);
    XCTAssertEqualObjects(adToken.additionalServer, @{@"key2" : @"value2"});
}

- (void)testInitWithNilAccessToken_shouldReturnNil
{
    ADTokenCacheItem *adToken = [[ADTokenCacheItem alloc] initWithLegacyAccessToken:nil];
    
    XCTAssertNil(adToken);
}

- (void)testInitWithRefreshToken_shouldInitADTokenCacheItem
{
    MSIDLegacyRefreshToken *refreshToken = [self adCreateRefreshToken];
    refreshToken.storageAuthority = [NSURL URLWithString:@"https://login.authority2.com/common"];
    ADUserInformation *expectedInformation = [self adCreateUserInformation:TEST_USER_ID
                                                             homeAccountId:refreshToken.clientInfo.accountIdentifier];

    ADTokenCacheItem *adToken = [[ADTokenCacheItem alloc] initWithLegacyRefreshToken:refreshToken];
    
    XCTAssertNotNil(adToken);
    XCTAssertEqualObjects(adToken.userInformation, expectedInformation);
    XCTAssertNil(adToken.expiresOn);
    XCTAssertNil(adToken.sessionKey);
    XCTAssertEqualObjects(adToken.refreshToken, @"refresh token");
    XCTAssertNil(adToken.accessTokenType);
    XCTAssertNil(adToken.accessToken);
    XCTAssertEqualObjects(adToken.familyId, @"family Id");
    XCTAssertEqualObjects(adToken.clientId, TEST_CLIENT_ID);
    XCTAssertEqualObjects(adToken.authority, TEST_AUTHORITY);
    XCTAssertEqualObjects(adToken.storageAuthority, @"https://login.authority2.com/common");
    XCTAssertNil(adToken.resource);
    XCTAssertEqualObjects(adToken.additionalServer, @{@"key2" : @"value2"});
}

- (void)testInitWithNilRefreshToken_shouldReturnNil
{
    ADTokenCacheItem *adToken = [[ADTokenCacheItem alloc] initWithLegacyRefreshToken:nil];
    
    XCTAssertNil(adToken);
}

- (void)testInitWithLegacySingleResourceToken_shouldInitADTokenCacheItem
{
    MSIDLegacySingleResourceToken *legacySingleResourceToken = [self adCreateLegacySingleResourceToken];
    legacySingleResourceToken.storageAuthority = [NSURL URLWithString:@"https://login.authority2.com/common"];
    ADUserInformation *expectedInformation = [self adCreateUserInformation:TEST_USER_ID
                                                             homeAccountId:legacySingleResourceToken.clientInfo.accountIdentifier];

    ADTokenCacheItem *adToken = [[ADTokenCacheItem alloc] initWithLegacySingleResourceToken:legacySingleResourceToken];
    
    XCTAssertNotNil(adToken);
    XCTAssertEqualObjects(adToken.userInformation, expectedInformation);
    XCTAssertEqualObjects(adToken.expiresOn, [NSDate dateWithTimeIntervalSince1970:1500000000]);
    XCTAssertNil(adToken.sessionKey);
    XCTAssertEqualObjects(adToken.refreshToken, @"refresh token");
    XCTAssertEqualObjects(adToken.accessTokenType, @"Bearer");
    XCTAssertEqualObjects(adToken.accessToken, @"access token");
    XCTAssertNil(adToken.familyId);
    XCTAssertEqualObjects(adToken.clientId, TEST_CLIENT_ID);
    XCTAssertEqualObjects(adToken.authority, TEST_AUTHORITY);
    XCTAssertEqualObjects(adToken.storageAuthority, @"https://login.authority2.com/common");
    XCTAssertEqualObjects(adToken.resource, TEST_RESOURCE);
    XCTAssertEqualObjects(adToken.additionalServer, @{@"key2" : @"value2"});
}

- (void)testInitWithTokenCacheItem_whenAccessToken_shouldInitADTokenCacheItem
{
    MSIDLegacyAccessToken *accessToken = [self adCreateAccessToken];
    MSIDLegacyTokenCacheItem *accessTokenCacheItem = [accessToken legacyTokenCacheItem];
    ADUserInformation *expectedInformation = [self adCreateUserInformation:TEST_USER_ID
                                                             homeAccountId:accessTokenCacheItem.clientInfo.accountIdentifier];

    ADTokenCacheItem *adToken = [[ADTokenCacheItem alloc] initWithMSIDLegacyTokenCacheItem:accessTokenCacheItem];
    
    XCTAssertNotNil(adToken);
    XCTAssertEqualObjects(adToken.userInformation, expectedInformation);
    XCTAssertEqualObjects(adToken.expiresOn, [NSDate dateWithTimeIntervalSince1970:1500000000]);
    XCTAssertNil(adToken.sessionKey);
    XCTAssertNil(adToken.refreshToken);
    XCTAssertEqualObjects(adToken.accessTokenType, @"Bearer");
    XCTAssertEqualObjects(adToken.accessToken, @"access token");
    XCTAssertNil(adToken.familyId);
    XCTAssertEqualObjects(adToken.clientId, TEST_CLIENT_ID);
    XCTAssertEqualObjects(adToken.authority, TEST_AUTHORITY);
    XCTAssertEqualObjects(adToken.resource, TEST_RESOURCE);
    XCTAssertEqualObjects(adToken.additionalServer, @{@"key2" : @"value2"});
}

- (void)testInitWithTokenCacheItem_whenRefreshToken_shouldInitADTokenCacheItem
{
    MSIDLegacyTokenCacheItem *refreshTokenCacheItem = [[self adCreateRefreshToken] legacyTokenCacheItem];
    ADUserInformation *expectedInformation = [self adCreateUserInformation:TEST_USER_ID
                                                             homeAccountId:refreshTokenCacheItem.clientInfo.accountIdentifier];
    
    ADTokenCacheItem *adToken = [[ADTokenCacheItem alloc] initWithMSIDLegacyTokenCacheItem:refreshTokenCacheItem];
    
    XCTAssertNotNil(adToken);
    XCTAssertEqualObjects(adToken.userInformation, expectedInformation);
    XCTAssertNil(adToken.expiresOn);
    XCTAssertNil(adToken.sessionKey);
    XCTAssertEqualObjects(adToken.refreshToken, @"refresh token");
    XCTAssertNil(adToken.accessTokenType);
    XCTAssertNil(adToken.accessToken);
    XCTAssertEqualObjects(adToken.familyId, @"family Id");
    XCTAssertEqualObjects(adToken.clientId, TEST_CLIENT_ID);
    XCTAssertEqualObjects(adToken.authority, TEST_AUTHORITY);
    XCTAssertNil(adToken.resource);
    XCTAssertEqualObjects(adToken.additionalServer, @{@"key2" : @"value2"});
}

- (void)testInitWithTokenCacheItem_whenSingleResourceRefreshToken_shouldInitADTokenCacheItem
{
    MSIDLegacyTokenCacheItem *legacySingleResourceToken = [[self adCreateLegacySingleResourceToken] legacyTokenCacheItem];
    ADUserInformation *expectedInformation = [self adCreateUserInformation:TEST_USER_ID
                                                             homeAccountId:legacySingleResourceToken.clientInfo.accountIdentifier];

    ADTokenCacheItem *adToken = [[ADTokenCacheItem alloc] initWithMSIDLegacyTokenCacheItem:legacySingleResourceToken];
    
    XCTAssertNotNil(adToken);
    XCTAssertEqualObjects(adToken.userInformation, expectedInformation);
    XCTAssertEqualObjects(adToken.expiresOn, [NSDate dateWithTimeIntervalSince1970:1500000000]);
    XCTAssertNil(adToken.sessionKey);
    XCTAssertEqualObjects(adToken.refreshToken, @"refresh token");
    XCTAssertEqualObjects(adToken.accessTokenType, @"Bearer");
    XCTAssertEqualObjects(adToken.accessToken, @"access token");
    XCTAssertNil(adToken.familyId);
    XCTAssertEqualObjects(adToken.clientId, TEST_CLIENT_ID);
    XCTAssertEqualObjects(adToken.authority, TEST_AUTHORITY);
    XCTAssertEqualObjects(adToken.resource, TEST_RESOURCE);
    XCTAssertEqualObjects(adToken.additionalServer, @{@"key2" : @"value2"});
}

- (void)testCreateTokenCacheIten_whenAccessToken_shouldReturnMSIDTokenCacheItem
{
    ADUserInformation *userInfo = [self adCreateUserInformation:TEST_USER_ID
                                                  homeAccountId:@"uid.utid"];
    
    ADTokenCacheItem *cacheItem = [ADTokenCacheItem new];
    cacheItem.clientId = TEST_CLIENT_ID;
    cacheItem.accessToken = @"access token";
    cacheItem.expiresOn = [NSDate dateWithTimeIntervalSince1970:1500000000];
    cacheItem.accessTokenType = @"Bearer";
    [cacheItem setValue:@{@"key2" : @"value2"} forKey:@"additionalServer"];
    cacheItem.resource = TEST_RESOURCE;
    cacheItem.authority = TEST_AUTHORITY;
    cacheItem.userInformation = userInfo;
    
    MSIDLegacyTokenCacheItem *msidItem = [cacheItem tokenCacheItem];
    
    XCTAssertEqualObjects(msidItem.clientId, TEST_CLIENT_ID);
    XCTAssertEqualObjects(msidItem.accessToken, @"access token");
    XCTAssertEqualObjects(msidItem.expiresOn, [NSDate dateWithTimeIntervalSince1970:1500000000]);
    XCTAssertEqualObjects(msidItem.oauthTokenType, @"Bearer");
    XCTAssertEqualObjects(msidItem.additionalInfo, @{@"key2" : @"value2"});
    XCTAssertEqualObjects(msidItem.target, TEST_RESOURCE);
    XCTAssertEqualObjects(msidItem.authority, [NSURL URLWithString:TEST_AUTHORITY]);
    XCTAssertEqualObjects(msidItem.idToken, userInfo.rawIdToken);
    XCTAssertEqual(msidItem.credentialType, MSIDAccessTokenType);
}

- (void)testCreateTokenCacheIten_whenRefreshToken_shouldReturnMSIDTokenCacheItem
{
    ADUserInformation *userInfo = [self adCreateUserInformation:TEST_USER_ID
                                                  homeAccountId:@"uid.utid"];
    
    ADTokenCacheItem *cacheItem = [ADTokenCacheItem new];
    cacheItem.clientId = TEST_CLIENT_ID;
    cacheItem.refreshToken = @"refresh token";
    cacheItem.familyId = @"foci";
    [cacheItem setValue:@{@"key2" : @"value2"} forKey:@"additionalServer"];
    cacheItem.authority = TEST_AUTHORITY;
    cacheItem.userInformation = userInfo;
    
    MSIDLegacyTokenCacheItem *msidItem = [cacheItem tokenCacheItem];
    
    XCTAssertEqualObjects(msidItem.clientId, TEST_CLIENT_ID);
    XCTAssertEqualObjects(msidItem.refreshToken, @"refresh token");
    XCTAssertEqualObjects(msidItem.familyId, @"foci");
    XCTAssertEqualObjects(msidItem.additionalInfo, @{@"key2" : @"value2"});
    XCTAssertEqualObjects(msidItem.authority, [NSURL URLWithString:TEST_AUTHORITY]);
    XCTAssertEqualObjects(msidItem.idToken, userInfo.rawIdToken);
    XCTAssertEqual(msidItem.credentialType, MSIDRefreshTokenType);
}

- (void)testCreateTokenCacheIten_whenSingleResourceRefreshToken_shouldReturnMSIDTokenCacheItem
{
    ADUserInformation *userInfo = [self adCreateUserInformation:TEST_USER_ID
                                                  homeAccountId:@"uid.utid"];
    
    ADTokenCacheItem *cacheItem = [ADTokenCacheItem new];
    cacheItem.clientId = TEST_CLIENT_ID;
    cacheItem.accessToken = @"access token";
    cacheItem.refreshToken = @"refresh token";
    cacheItem.expiresOn = [NSDate dateWithTimeIntervalSince1970:1500000000];
    cacheItem.accessTokenType = @"Bearer";
    [cacheItem setValue:@{@"key2" : @"value2"} forKey:@"additionalServer"];
    cacheItem.resource = TEST_RESOURCE;
    cacheItem.authority = TEST_AUTHORITY;
    cacheItem.userInformation = userInfo;
    
    MSIDLegacyTokenCacheItem *msidItem = [cacheItem tokenCacheItem];
    
    XCTAssertEqualObjects(msidItem.clientId, TEST_CLIENT_ID);
    XCTAssertEqualObjects(msidItem.accessToken, @"access token");
    XCTAssertEqualObjects(msidItem.refreshToken, @"refresh token");
    XCTAssertEqualObjects(msidItem.expiresOn, [NSDate dateWithTimeIntervalSince1970:1500000000]);
    XCTAssertEqualObjects(msidItem.oauthTokenType, @"Bearer");
    XCTAssertEqualObjects(msidItem.additionalInfo, @{@"key2" : @"value2"});
    XCTAssertEqualObjects(msidItem.target, TEST_RESOURCE);
    XCTAssertEqualObjects(msidItem.authority, [NSURL URLWithString:TEST_AUTHORITY]);
    XCTAssertEqualObjects(msidItem.idToken, userInfo.rawIdToken);
    XCTAssertEqual(msidItem.credentialType, MSIDLegacySingleResourceTokenType);
}

- (void)testInitWithNilSingleResourceToken_shouldReturnNil
{
    ADTokenCacheItem *adToken = [[ADTokenCacheItem alloc] initWithLegacySingleResourceToken:nil];
    
    XCTAssertNil(adToken);
}

@end
