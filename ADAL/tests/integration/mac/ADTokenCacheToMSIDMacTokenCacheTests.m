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
#import "ADTokenCacheItem.h"
#import "MSIDMacTokenCache.h"
#import "ADTokenCache.h"
#import "ADTokenCache+Internal.h"
#import "MSIDTokenCacheKey.h"
#import "MSIDToken.h"
#import "ADUserInformation.h"
#import "ADTokenCacheKey.h"

@interface ADTokenCacheToMSIDMacTokenCacheTests : XCTestCase

@end

@implementation ADTokenCacheToMSIDMacTokenCacheTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

#pragma mark - ADTokenCacheKey -> MSIDMacTokenCache

- (void)testMSIDMacTokenCacheGetItemFromADALBlob_whenBlobContainsItem_shouldReturnThatItem
{
    ADTokenCache *adTokenCache = [ADTokenCache new];
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
    BOOL result = [adTokenCache addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);
    XCTAssertTrue(result);
    
    MSIDMacTokenCache *msidMacTokenCache = [MSIDMacTokenCache new];
    MSIDTokenCacheKey *msidTokenCacheKey = [MSIDTokenCacheKey keyWithAuthority:[[NSURL alloc] initWithString:TEST_AUTHORITY] clientId:TEST_CLIENT_ID resource:TEST_RESOURCE upn:@"eric_cartman@contoso.com"];
    
    // Read from blob created by ADTokenCache.
    NSData *data = [adTokenCache serialize];
    result = [msidMacTokenCache deserialize:data error:&error];
    XCTAssertNil(error);
    XCTAssertTrue(result);
    
    MSIDToken *msidToken = [msidMacTokenCache itemWithKey:msidTokenCacheKey serializer:nil context:nil error:&error];
    
    XCTAssertNil(error);
    XCTAssertNotNil(msidToken);
}

#pragma mark - MSIDMacTokenCache -> ADTokenCacheKey

- (void)testADTokenCacheKeyGetItemFromMSIDBlob_whenBlobContainsItem_shouldReturnThatItem
{
    MSIDMacTokenCache *msidMacTokenCache = [MSIDMacTokenCache new];
    
    MSIDTokenCacheKey *msidTokenCacheKey = [MSIDTokenCacheKey keyWithAuthority:[[NSURL alloc] initWithString:TEST_AUTHORITY] clientId:TEST_CLIENT_ID resource:TEST_RESOURCE upn:@"eric_cartman@contoso.com"];
    
    MSIDToken *token = [MSIDToken new];
    [token setValue:TEST_ACCESS_TOKEN_TYPE forKey:@"token"];
    NSString *rawIdToken = [self adCreateUserInformation:TEST_USER_ID].rawIdToken;
    [token setValue:rawIdToken forKey:@"idToken"];
    [token setValue:[NSDate dateWithTimeIntervalSince1970:1500000000] forKey:@"expiresOn"];
    [token setValue:@"familyId value" forKey:@"familyId"];
    MSIDClientInfo *clientInfo = [MSIDClientInfo new];
    [clientInfo setValue:@"raw client info" forKey:@"rawClientInfo"];
    [token setValue:clientInfo forKey:@"clientInfo"];
    [token setValue:@{@"key2" : @"value2"} forKey:@"additionalServerInfo"];
    [token setValue:TEST_RESOURCE forKey:@"resource"];
    [token setValue:[[NSURL alloc] initWithString:TEST_AUTHORITY] forKey:@"authority"];
    [token setValue:TEST_CLIENT_ID forKey:@"clientId"];
    [token setValue:[[NSOrderedSet alloc] initWithArray:@[@1, @2]] forKey:@"scopes"];
    
    NSError *error;
    BOOL result = [msidMacTokenCache setItem:token key:msidTokenCacheKey serializer:nil context:nil error:&error];
    XCTAssertNil(error);
    XCTAssertTrue(result);
    
    ADTokenCacheKey *key = [ADTokenCacheKey keyWithAuthority:TEST_AUTHORITY resource:TEST_RESOURCE clientId:TEST_CLIENT_ID error:nil];
    ADTokenCache *adTokenCache = [ADTokenCache new];
    
    // Read from blob created by MSIDMacTokenCache.
    NSData *data = [msidMacTokenCache serialize];
    result = [adTokenCache deserialize:data error:&error];
    XCTAssertNil(error);
    XCTAssertTrue(result);
    
    ADTokenCacheItem *item = [adTokenCache getItemWithKey:key userId:TEST_USER_ID correlationId:nil error:&error];
    
    XCTAssertNil(error);
    XCTAssertNotNil(item);
}

@end
