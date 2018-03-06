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
#import "MSIDToken.h"
#import "MSIDKeyedArchiverSerializer.h"
#import "ADTokenCacheItem.h"
#import "ADUserInformation.h"

@interface ADTokenCacheItemArchivingToMSIDTokenTests : ADTestCase

@end

@implementation ADTokenCacheItemArchivingToMSIDTokenTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

#pragma mark - ADTokenCacheItem -> MSIDToken

- (void)testDeserialize_whenAccessTokenIsValidRefreshTokenNil_shouldReturnAccessMSIDToken
{
    MSIDKeyedArchiverSerializer *serializer = [MSIDKeyedArchiverSerializer new];
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
    NSData *data = [NSKeyedArchiver archivedDataWithRootObject:item];
    
    MSIDToken *resultToken = [serializer deserialize:data];
    
    XCTAssertTrue([resultToken isKindOfClass:MSIDToken.class]);
    XCTAssertNotNil(resultToken);
    XCTAssertEqualObjects(resultToken.resource, TEST_RESOURCE);
    XCTAssertEqualObjects(resultToken.authority.absoluteString, TEST_AUTHORITY);
    XCTAssertEqualObjects(resultToken.clientId, TEST_CLIENT_ID);
    XCTAssertEqualObjects(resultToken.token, TEST_ACCESS_TOKEN);
    XCTAssertEqual(resultToken.tokenType, MSIDTokenTypeAccessToken);
    XCTAssertEqualObjects(resultToken.expiresOn, date);
    XCTAssertEqualObjects(resultToken.idToken, item.userInformation.rawIdToken);
    XCTAssertEqualObjects(resultToken.additionalServerInfo, additionalServerInfo);
    XCTAssertNil(resultToken.scopes);
    XCTAssertNil(resultToken.clientInfo);
}

- (void)testDeserialize_whenAccessTokenIsNilRefreshTokenIsValid_shouldReturnRefreshMSIDToken
{
    MSIDKeyedArchiverSerializer *serializer = [MSIDKeyedArchiverSerializer new];
    NSDate *date = [NSDate new];
    NSDictionary *additionalServerInfo = @{@"key1": @"value1"};
    NSData *sessionKey = [@"test" dataUsingEncoding:NSUTF8StringEncoding];
    ADTokenCacheItem *item = [ADTokenCacheItem new];
    item.resource = TEST_RESOURCE;
    item.authority = TEST_AUTHORITY;
    item.clientId = TEST_CLIENT_ID;
    item.accessToken = nil;
    item.refreshToken = TEST_REFRESH_TOKEN;
    item.expiresOn = date;
    item.userInformation = [self adCreateUserInformation:TEST_USER_ID];
    [item setValue:additionalServerInfo forKey:@"additionalServer"];
    [item setValue:sessionKey forKey:@"sessionKey"];
    NSData *data = [NSKeyedArchiver archivedDataWithRootObject:item];
    
    MSIDToken *resultToken = [serializer deserialize:data];
    
    XCTAssertTrue([resultToken isKindOfClass:MSIDToken.class]);
    XCTAssertNotNil(resultToken);
    XCTAssertEqualObjects(resultToken.resource, TEST_RESOURCE);
    XCTAssertEqualObjects(resultToken.authority.absoluteString, TEST_AUTHORITY);
    XCTAssertEqualObjects(resultToken.clientId, TEST_CLIENT_ID);
    XCTAssertEqualObjects(resultToken.token, TEST_REFRESH_TOKEN);
    XCTAssertEqual(resultToken.tokenType, MSIDTokenTypeRefreshToken);
    XCTAssertEqualObjects(resultToken.expiresOn, date);
    XCTAssertEqualObjects(resultToken.idToken, item.userInformation.rawIdToken);
    XCTAssertEqualObjects(resultToken.additionalServerInfo, additionalServerInfo);
    XCTAssertNil(resultToken.scopes);
    XCTAssertNil(resultToken.clientInfo);
}

- (void)testDeserialize_whenAccessTokenIsValidRefreshTokenIsValid_shouldReturnRefreshMSIDToken
{
    MSIDKeyedArchiverSerializer *serializer = [MSIDKeyedArchiverSerializer new];
    NSDate *date = [NSDate new];
    NSDictionary *additionalServerInfo = @{@"key1": @"value1"};
    NSData *sessionKey = [@"test" dataUsingEncoding:NSUTF8StringEncoding];
    ADTokenCacheItem *item = [ADTokenCacheItem new];
    item.resource = TEST_RESOURCE;
    item.authority = TEST_AUTHORITY;
    item.clientId = TEST_CLIENT_ID;
    item.refreshToken = TEST_REFRESH_TOKEN;
    item.expiresOn = date;
    item.userInformation = [self adCreateUserInformation:TEST_USER_ID];
    [item setValue:additionalServerInfo forKey:@"additionalServer"];
    [item setValue:sessionKey forKey:@"sessionKey"];
    NSData *data = [NSKeyedArchiver archivedDataWithRootObject:item];
    
    MSIDToken *resultToken = [serializer deserialize:data];
    
    XCTAssertTrue([resultToken isKindOfClass:MSIDToken.class]);
    XCTAssertNotNil(resultToken);
    XCTAssertEqualObjects(resultToken.resource, TEST_RESOURCE);
    XCTAssertEqualObjects(resultToken.authority.absoluteString, TEST_AUTHORITY);
    XCTAssertEqualObjects(resultToken.clientId, TEST_CLIENT_ID);
    XCTAssertEqualObjects(resultToken.token, TEST_REFRESH_TOKEN);
    XCTAssertEqual(resultToken.tokenType, MSIDTokenTypeRefreshToken);
    XCTAssertEqualObjects(resultToken.expiresOn, date);
    XCTAssertEqualObjects(resultToken.idToken, item.userInformation.rawIdToken);
    XCTAssertEqualObjects(resultToken.additionalServerInfo, additionalServerInfo);
    XCTAssertNil(resultToken.scopes);
    XCTAssertNil(resultToken.clientInfo);
}

#pragma mark - MSIDToken -> ADTokenCacheItem

- (void)testSerialize_whenAccessMSIDToken_shouldUnarchiveAsAccessADTokenCacheItem
{
    MSIDToken *msidToken = [self createAccessMSIDToken];
    MSIDKeyedArchiverSerializer *serializer = [MSIDKeyedArchiverSerializer new];
    NSData *data = [serializer serialize:msidToken];
    
    ADTokenCacheItem *adToken = [NSKeyedUnarchiver unarchiveObjectWithData:data];
    
    XCTAssertNotNil(adToken);
    XCTAssertTrue([adToken isKindOfClass:ADTokenCacheItem.class]);
    XCTAssertEqualObjects(adToken.resource, TEST_RESOURCE);
    XCTAssertEqualObjects(adToken.authority, TEST_AUTHORITY);
    XCTAssertEqualObjects(adToken.clientId, TEST_CLIENT_ID);
    XCTAssertEqualObjects(adToken.accessToken, TEST_ACCESS_TOKEN_TYPE);
    XCTAssertEqualObjects(adToken.accessTokenType, @"Bearer");
    XCTAssertNil(adToken.refreshToken);
    XCTAssertEqualObjects(adToken.expiresOn, [NSDate dateWithTimeIntervalSince1970:1500000000]);
    XCTAssertEqualObjects(adToken.userInformation, [self adCreateUserInformation:TEST_USER_ID]);
    XCTAssertEqualObjects(adToken.familyId, @"familyId value");
}

- (void)testSerialize_whenRefreshMSIDToken_shouldUnarchiveAsRefreshADTokenCacheItem
{
    MSIDToken *msidToken = [self createRefreshMSIDToken];
    MSIDKeyedArchiverSerializer *serializer = [MSIDKeyedArchiverSerializer new];
    NSData *data = [serializer serialize:msidToken];
    
    ADTokenCacheItem *adToken = [NSKeyedUnarchiver unarchiveObjectWithData:data];
    
    XCTAssertNotNil(adToken);
    XCTAssertTrue([adToken isKindOfClass:ADTokenCacheItem.class]);
    XCTAssertEqualObjects(adToken.resource, TEST_RESOURCE);
    XCTAssertEqualObjects(adToken.authority, TEST_AUTHORITY);
    XCTAssertEqualObjects(adToken.clientId, TEST_CLIENT_ID);
    XCTAssertEqualObjects(adToken.refreshToken, TEST_REFRESH_TOKEN);
    XCTAssertEqualObjects(adToken.accessTokenType, @"Bearer");
    XCTAssertNil(adToken.accessToken);
    XCTAssertEqualObjects(adToken.expiresOn, [NSDate dateWithTimeIntervalSince1970:1500000000]);
    XCTAssertEqualObjects(adToken.userInformation, [self adCreateUserInformation:TEST_USER_ID]);
    XCTAssertEqualObjects(adToken.familyId, @"familyId value");
}

#pragma mark - Private

- (MSIDToken *)createAccessMSIDToken
{
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
    
    return token;
}

- (MSIDToken *)createRefreshMSIDToken
{
    MSIDToken *token = [MSIDToken new];
    [token setValue:TEST_REFRESH_TOKEN forKey:@"token"];
    [token setValue:[[NSNumber alloc] initWithInt:MSIDTokenTypeRefreshToken] forKey:@"tokenType"];
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
    
    return token;
}

@end
