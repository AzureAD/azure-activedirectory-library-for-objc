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
#import "MSIDAccessToken.h"
#import "MSIDRefreshToken.h"
#import "MSIDLegacySingleResourceToken.h"
#import "XCTestCase+TestHelperMethods.h"

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
    MSIDAccessToken *accessToken = [self adCreateAccessToken];
    ADUserInformation *expectedInformation = [self adCreateUserInformation:TEST_USER_ID
                                                                homeUserId:accessToken.clientInfo.userIdentifier];
    
    ADTokenCacheItem *adToken = [[ADTokenCacheItem alloc] initWithAccessToken:accessToken];
    
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
    XCTAssertEqualObjects(adToken.additionalClient, @{});
}

- (void)testInitWithNilAccessToken_shouldReturnNil
{
    ADTokenCacheItem *adToken = [[ADTokenCacheItem alloc] initWithAccessToken:nil];
    
    XCTAssertNil(adToken);
}

- (void)testInitWithRefreshToken_shouldInitADTokenCacheItem
{
    MSIDRefreshToken *refreshToken = [self adCreateRefreshToken];
    ADUserInformation *expectedInformation = [self adCreateUserInformation:TEST_USER_ID
                                                                homeUserId:refreshToken.clientInfo.userIdentifier];
    
    ADTokenCacheItem *adToken = [[ADTokenCacheItem alloc] initWithRefreshToken:refreshToken];
    
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
    XCTAssertEqualObjects(adToken.additionalClient, @{});
}

- (void)testInitWithNilRefreshToken_shouldReturnNil
{
    ADTokenCacheItem *adToken = [[ADTokenCacheItem alloc] initWithRefreshToken:nil];
    
    XCTAssertNil(adToken);
}

- (void)testInitWithLegacySingleResourceToken_shouldInitADTokenCacheItem
{
    MSIDLegacySingleResourceToken *legacySingleResourceToken = [self adCreateLegacySingleResourceToken];
    ADUserInformation *expectedInformation = [self adCreateUserInformation:TEST_USER_ID
                                                                homeUserId:legacySingleResourceToken.clientInfo.userIdentifier];
    
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
    XCTAssertEqualObjects(adToken.resource, TEST_RESOURCE);
    XCTAssertEqualObjects(adToken.additionalServer, @{@"key2" : @"value2"});
    XCTAssertEqualObjects(adToken.additionalClient, @{});
}

- (void)testInitWithNilSingleResourceToken_shouldReturnNil
{
    ADTokenCacheItem *adToken = [[ADTokenCacheItem alloc] initWithLegacySingleResourceToken:nil];
    
    XCTAssertNil(adToken);
}

@end
