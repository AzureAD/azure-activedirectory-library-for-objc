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
#import "ADLegacyKeychainTokenCache.h"
#import "ADTokenCacheItem.h"
#import "ADUserInformation.h"
#import "MSIDKeychainTokenCache.h"
#import "MSIDKeyedArchiverSerializer.h"
#import "MSIDLegacyTokenCacheKey.h"
#import "MSIDLegacyTokenCacheItem.h"
#import "MSIDKeychainTokenCache+MSIDTestsUtil.h"
#import "ADTokenCacheKey.h"
#import "MSIDLegacyTokenCacheKey.h"

@interface ADKeychainTokenCacheToMSIDKeychainTokenCacheTests : XCTestCase

@end

@implementation ADKeychainTokenCacheToMSIDKeychainTokenCacheTests

- (void)setUp
{
    [super setUp];
    
    [MSIDKeychainTokenCache reset];
}

- (void)tearDown
{
    [super tearDown];
    
    [MSIDKeychainTokenCache reset];
}

#pragma mark - ADKeychainTokenCache -> MSIDKeychainTokenCache

- (void)test_saveADALTokenInADALKeychain_MSIDKeychainShouldFindMSIDToken
{
    ADLegacyKeychainTokenCache *adKeychainTokenCache = [ADLegacyKeychainTokenCache new];
    NSDate *date = [NSDate new];
    NSDictionary *additionalServerInfo = @{@"key1": @"value1"};
    NSData *sessionKey = [@"test" dataUsingEncoding:NSUTF8StringEncoding];
    ADTokenCacheItem *item = [ADTokenCacheItem new];
    item.resource = TEST_RESOURCE;
    item.authority = TEST_AUTHORITY;
    item.clientId = TEST_CLIENT_ID;
    item.accessToken = TEST_ACCESS_TOKEN;
    item.expiresOn = date;
    item.userInformation = [self adCreateUserInformation:TEST_USER_ID];
    [item setValue:additionalServerInfo forKey:@"additionalServer"];
    [item setValue:sessionKey forKey:@"sessionKey"];
    
    NSError *error;
    BOOL result = [adKeychainTokenCache addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);
    XCTAssertTrue(result);
    
    
    MSIDKeychainTokenCache *msidKeychainTokenCache = [MSIDKeychainTokenCache new];

    MSIDLegacyTokenCacheKey *msidTokenCacheKey = [[MSIDLegacyTokenCacheKey alloc] initWithAuthority:[[NSURL alloc] initWithString:TEST_AUTHORITY]
                                                                                           clientId:TEST_CLIENT_ID
                                                                                           resource:TEST_RESOURCE
                                                                                       legacyUserId:TEST_USER_ID];
    
    XCTAssertEqualObjects(msidTokenCacheKey.account, @"ZXJpY19jYXJ0bWFuQGNvbnRvc28uY29t");
    XCTAssertEqualObjects(msidTokenCacheKey.service, @"MSOpenTech.ADAL.1|aHR0cHM6Ly9sb2dpbi53aW5kb3dzLm5ldC9jb250b3NvLmNvbQ|cmVzb3VyY2U|YzNjN2Y1ZTUtNzE1My00NGQ0LTkwZTYtMzI5Njg2ZDQ4ZDc2");
    
    MSIDCredentialCacheItem *tokenCacheItem = [msidKeychainTokenCache tokenWithKey:msidTokenCacheKey serializer:[MSIDKeyedArchiverSerializer new] context:nil error:&error];
    
    XCTAssertNil(error);
    XCTAssertNotNil(tokenCacheItem);
}

#pragma mark - MSIDKeychainTokenCache -> ADKeychainTokenCache

- (void)test_saveMSIDTokenInMSIDKeychain_ADALKeychainShouldFindADALToken
{
    MSIDKeychainTokenCache *msidKeychainTokenCache = [MSIDKeychainTokenCache new];
    
    MSIDLegacyTokenCacheKey *msidTokenCacheKey = [[MSIDLegacyTokenCacheKey alloc] initWithAuthority:[[NSURL alloc] initWithString:TEST_AUTHORITY]
                                                                                           clientId:TEST_CLIENT_ID
                                                                                           resource:TEST_RESOURCE
                                                                                       legacyUserId:TEST_USER_ID];

    XCTAssertEqualObjects(msidTokenCacheKey.account, @"ZXJpY19jYXJ0bWFuQGNvbnRvc28uY29t");
    XCTAssertEqualObjects(msidTokenCacheKey.service, @"MSOpenTech.ADAL.1|aHR0cHM6Ly9sb2dpbi53aW5kb3dzLm5ldC9jb250b3NvLmNvbQ|cmVzb3VyY2U|YzNjN2Y1ZTUtNzE1My00NGQ0LTkwZTYtMzI5Njg2ZDQ4ZDc2");
    
    MSIDLegacyTokenCacheItem *tokenCacheItem = [self adCreateAccessMSIDTokenCacheItem];
    
    NSError *error;
    BOOL result = [msidKeychainTokenCache saveToken:tokenCacheItem key:msidTokenCacheKey serializer:[MSIDKeyedArchiverSerializer new] context:nil error:&error];
    
    XCTAssertNil(error);
    XCTAssertTrue(result);
    
    ADTokenCacheKey *key = [ADTokenCacheKey keyWithAuthority:TEST_AUTHORITY resource:TEST_RESOURCE clientId:TEST_CLIENT_ID error:nil];
    ADLegacyKeychainTokenCache *adKeychainTokenCache = [ADLegacyKeychainTokenCache new];
    ADTokenCacheItem *item = [adKeychainTokenCache getItemWithKey:key userId:TEST_USER_ID correlationId:nil error:&error];
    
    XCTAssertNil(error);
    XCTAssertNotNil(item);
}

@end
