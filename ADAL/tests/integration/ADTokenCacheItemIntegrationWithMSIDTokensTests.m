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
#import "MSIDAdfsToken.h"

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
    MSIDAccessToken *accessToken = [self createAccessToken];
    
    ADTokenCacheItem *adToken = [[ADTokenCacheItem alloc] initWithAccessToken:accessToken];
    
    XCTAssertNotNil(adToken);
    XCTAssertEqualObjects(adToken.userInformation, [self adCreateUserInformation:TEST_USER_ID]);
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

- (void)testInitWithRefreshToken_shouldInitADTokenCacheItem
{
    MSIDRefreshToken *refreshToken = [self createRefreshToken];
    
    ADTokenCacheItem *adToken = [[ADTokenCacheItem alloc] initWithRefreshToken:refreshToken];
    
    XCTAssertNotNil(adToken);
    XCTAssertEqualObjects(adToken.userInformation, [self adCreateUserInformation:TEST_USER_ID]);
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

- (void)testInitWithADFSToken_shouldInitADTokenCacheItem
{
    MSIDAdfsToken *adfsToken = [self createADFSToken];
    
    ADTokenCacheItem *adToken = [[ADTokenCacheItem alloc] initWithADFSToken:adfsToken];
    
    XCTAssertNotNil(adToken);
    XCTAssertEqualObjects(adToken.userInformation, [self adCreateUserInformation:TEST_USER_ID]);
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

#pragma mark - Private

- (MSIDAccessToken *)createAccessToken
{
    MSIDAccessToken *accessToken = [MSIDAccessToken new];
    [self initBaseToken:accessToken];
    [self initAccessToken:accessToken];
    
    return accessToken;
}

- (MSIDRefreshToken *)createRefreshToken
{
    MSIDRefreshToken *refreshToken = [MSIDRefreshToken new];
    [self initBaseToken:refreshToken];
    
    [refreshToken setValue:@"refresh token" forKey:@"refreshToken"];
    [refreshToken setValue:@"family Id" forKey:@"familyId"];
    NSString *rawIdToken = [self adCreateUserInformation:TEST_USER_ID].rawIdToken;
    [refreshToken setValue:rawIdToken forKey:@"idToken"];
    
    return refreshToken;
}

- (MSIDAdfsToken *)createADFSToken
{
    MSIDAdfsToken *adfsToken = [MSIDAdfsToken new];
    [self initBaseToken:adfsToken];
    [self initAccessToken:adfsToken];
    
    [adfsToken setValue:@"refresh token" forKey:@"refreshToken"];
    NSString *rawIdToken = [self adCreateUserInformation:TEST_USER_ID].rawIdToken;
    [adfsToken setValue:rawIdToken forKey:@"idToken"];
    
    return adfsToken;
}

- (void)initBaseToken:(MSIDBaseToken *)baseToken
{
    [baseToken setValue:[[NSURL alloc] initWithString:TEST_AUTHORITY] forKey:@"authority"];
    [baseToken setValue:TEST_CLIENT_ID forKey:@"clientId"];
    [baseToken setValue:@"unique User Id" forKey:@"uniqueUserId"];
    MSIDClientInfo *clientInfo = [MSIDClientInfo new];
    [clientInfo setValue:@"raw client info" forKey:@"rawClientInfo"];
    [baseToken setValue:clientInfo forKey:@"clientInfo"];
    [baseToken setValue:@{@"key2" : @"value2"} forKey:@"additionalInfo"];
    [baseToken setValue:@"Eric Cartman" forKey:@"username"];
}

- (void)initAccessToken:(MSIDAccessToken *)accessToken
{
    [accessToken setValue:[NSDate dateWithTimeIntervalSince1970:1500000000] forKey:@"expiresOn"];
    [accessToken setValue:[NSDate dateWithTimeIntervalSince1970:1100000000] forKey:@"cachedAt"];
    [accessToken setValue:@"access token" forKey:@"accessToken"];
    NSString *rawIdToken = [self adCreateUserInformation:TEST_USER_ID].rawIdToken;
    [accessToken setValue:rawIdToken forKey:@"idToken"];
    [accessToken setValue:TEST_RESOURCE forKey:@"target"];
}

@end
