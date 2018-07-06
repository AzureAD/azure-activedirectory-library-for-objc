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
#import "ADAuthenticationContext.h"
#import "ADAuthenticationResult+Internal.h"
#import "ADTokenCacheItem.h"
#import "XCTestCase+TestHelperMethods.h"
#import "ADUserInformation.h"
#import "MSIDClientInfo.h"
#import "MSIDBrokerResponse.h"

@interface ADAuthenticationResultTests : ADTestCase

@end

@implementation ADAuthenticationResultTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

#pragma mark - Initialization

- (void)testNew_shouldThrow
{
    XCTAssertThrows([ADAuthenticationResult new]);
}

- (void)testInit_shouldThrow
{
    XCTAssertThrows([[ADAuthenticationResult alloc] init]);
}

#pragma mark - resultFromCancellation

- (void)testResultFromCancellation_whenNoParameters_shouldReturnCancelledStatusAndErrorTokenCacheItemNil
{
    ADAuthenticationResult *result = [ADAuthenticationResult resultFromCancellation];
    
    XCTAssertNotNil(result);
    XCTAssertEqual(result.status, AD_USER_CANCELLED);
    ADAssertLongEquals(result.error.code, AD_ERROR_UI_USER_CANCEL);
    XCTAssertNil(result.tokenCacheItem);
}

#pragma mark - resultFromError

- (void)testResultFromError_whenErrorIsUnexpectedInternal_shouldReturnStatusFailedSameErrorAsWasProvidedTokenChacheItemNil
{
    ADAuthenticationError *error = [ADAuthenticationError unexpectedInternalError:@"something" correlationId:nil];
    ADAuthenticationResult *result = [ADAuthenticationResult resultFromError:error];
    
    XCTAssertNotNil(result);
    XCTAssertEqual(result.status, AD_FAILED);
    XCTAssertEqualObjects(result.error, error);
    XCTAssertNil(result.tokenCacheItem);
}

#pragma mark - resultFromTokenCacheItem

- (void)testResultFromtokenCacheItem_whenItemNilMRRTNoCorrelationIdNil_shouldReturnStatusFailedErrorUnexpectedTokenChacheItemNil
{
    ADAuthenticationResult *result = [ADAuthenticationResult resultFromTokenCacheItem:nil multiResourceRefreshToken:NO correlationId:nil];

    XCTAssertNotNil(result);
    XCTAssertEqual(result.status, AD_FAILED);
    ADAssertLongEquals(result.error.code, AD_ERROR_UNEXPECTED);
    XCTAssertNil(result.tokenCacheItem);
}

- (void)testResultFromtokenCacheItem_whenItemValidMRRTNoCorrelationIdNil_shouldReturnStatusSucceededErrorNilTokenChacheItemSameAsWasProvided
{
    ADTokenCacheItem *item = [ADTokenCacheItem new];
    item.resource = @"resource";
    item.authority = @"https://login.windows.net/mytennant.com";
    item.clientId = @"clientId";
    item.accessToken = @"accessToken";
    item.accessTokenType = @"tokenType";
    item.refreshToken = @"refreshToken";
    item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:30];
    
    ADAuthenticationResult *result = [ADAuthenticationResult resultFromTokenCacheItem:item multiResourceRefreshToken:NO correlationId:nil];
    
    XCTAssertNotNil(result);
    XCTAssertNil(result.error);
    XCTAssertEqual(result.status, AD_SUCCEEDED);
    XCTAssertEqualObjects(item, result.tokenCacheItem);
}

#pragma mark - resultFromBrokerResponse

- (void)testResultFromBrokerResponse_whenResponseIsValidFromCommon_shouldReturnResultWithTokenCacheItemWithAccessToken
{
    // Not a complete IDToken, but enough to get past the parser. If you're seeing this test fail and have recently
    // changed the idtoken code then this might have to be tweaked.
    NSString* idtokenJSON = @"{\"typ\":\"JWT\",\"aud\":\"c3c7f5e5-7153-44d4-90e6-329686d48d76\",\"iss\":\"https://sts.windows.net/6fd1f5cd-a94c-4335-889b-6c598e6d8048/\",\"iat\":1387224169,\"nbf\":1387224169,\"exp\":1387227769,\"ver\":\"1.0\",\"tid\":\"6fd1f5cd-a94c-4335-889b-6c598e6d8048\",\"oid\":\"53c6acf2-2742-4538-918d-e78257ec8516\",\"upn\":\"myfakeuser@contoso.com\",\"unique_name\":\"myfakeuser@contoso.com\",\"sub\":\"0DxnAlLi12IvGL_dG3dDMk3zp6AQHnjgogyim5AWpSc\",\"family_name\":\"User\",\"given_name\":\"Fake\"}";
    NSDictionary* response = @{
                               @"authority" : @"http://login.windows.net/common",
                               @"access_token" : @"MyFakeAccessToken",
                               @"refresh_token" : @"MyFakeRefreshToken",
                               @"resource" : @"MyFakeResource",
                               @"expires_on" : @"1444166530.336707",
                               @"client_id" : @"27AD83C9-FC05-4A6C-AF01-36EDA42ED18F",
                               @"correlation_id" : @"5EF4B8D0-A734-441B-887D-FBB8257C0784",
                               @"id_token" : [idtokenJSON msidBase64UrlEncode],
                               @"user_id" : @"myfakeuser@contoso.com",
                               @"client_info" : [self adCreateClientInfo].rawClientInfo
                               };
    
    NSError *error = nil;
    MSIDBrokerResponse *brokerResponse = [[MSIDBrokerResponse alloc] initWithDictionary:response error:&error];
    
    XCTAssertNotNil(brokerResponse);
    XCTAssertNil(error);
    
    ADAuthenticationResult *result = [ADAuthenticationResult resultFromBrokerResponse:brokerResponse];
    
    XCTAssertNotNil(result);
    XCTAssertNil(result.error);
    XCTAssertNotNil(result.tokenCacheItem);
    XCTAssertEqual(result.tokenCacheItem.expiresOn.timeIntervalSince1970, 1444166530);
    XCTAssertEqualObjects(result.tokenCacheItem.accessToken, @"MyFakeAccessToken");
    XCTAssertEqualObjects(result.tokenCacheItem.refreshToken, @"MyFakeRefreshToken");
    XCTAssertEqualObjects(result.tokenCacheItem.resource, @"MyFakeResource");
    XCTAssertEqualObjects(result.tokenCacheItem.clientId, @"27AD83C9-FC05-4A6C-AF01-36EDA42ED18F");
    XCTAssertEqualObjects(result.tokenCacheItem.userInformation.userId, @"myfakeuser@contoso.com");
}

- (void)testResultFromBrokerResponse_whenResponseIsValidWithSpecificTenantAndVTFlag_shouldReturnResultWithTokenCacheItemWithAccessToken
{
    // Not a complete IDToken, but enough to get past the parser. If you're seeing this test fail and have recently
    // changed the idtoken code then this might have to be tweaked.
    NSString* idtokenJSON = @"{\"typ\":\"JWT\",\"aud\":\"c3c7f5e5-7153-44d4-90e6-329686d48d76\",\"iss\":\"https://sts.windows.net/6fd1f5cd-a94c-4335-889b-6c598e6d8048/\",\"iat\":1387224169,\"nbf\":1387224169,\"exp\":1387227769,\"ver\":\"1.0\",\"tid\":\"6fd1f5cd-a94c-4335-889b-6c598e6d8048\",\"oid\":\"53c6acf2-2742-4538-918d-e78257ec8516\",\"upn\":\"myfakeuser@contoso.com\",\"unique_name\":\"myfakeuser@contoso.com\",\"sub\":\"0DxnAlLi12IvGL_dG3dDMk3zp6AQHnjgogyim5AWpSc\",\"family_name\":\"User\",\"given_name\":\"Fake\"}";
    NSDictionary* response = @{
                               @"authority" : @"http://login.windows.net/contoso.com",
                               @"vt" : @"1",
                               @"access_token" : @"MyFakeAccessToken",
                               @"refresh_token" : @"MyFakeRefreshToken",
                               @"resource" : @"MyFakeResource",
                               @"expires_on" : @"1444166530.336707",
                               @"client_id" : @"27AD83C9-FC05-4A6C-AF01-36EDA42ED18F",
                               @"correlation_id" : @"5EF4B8D0-A734-441B-887D-FBB8257C0784",
                               @"id_token" : [idtokenJSON msidBase64UrlEncode],
                               @"user_id" : @"myfakeuser@contoso.com",
                               @"client_info" : [self adCreateClientInfo].rawClientInfo
                               };
    
    NSError *error = nil;
    MSIDBrokerResponse *brokerResponse = [[MSIDBrokerResponse alloc] initWithDictionary:response error:&error];
    
    XCTAssertNotNil(brokerResponse);
    XCTAssertNil(error);
    
    ADAuthenticationResult *result = [ADAuthenticationResult resultFromBrokerResponse:brokerResponse];
    
    XCTAssertNotNil(result);
    XCTAssertNil(result.error);
    XCTAssertNotNil(result.tokenCacheItem);
    XCTAssertEqual(result.tokenCacheItem.expiresOn.timeIntervalSince1970, 1444166530);
    XCTAssertEqualObjects(result.tokenCacheItem.accessToken, @"MyFakeAccessToken");
    XCTAssertEqualObjects(result.tokenCacheItem.refreshToken, @"MyFakeRefreshToken");
    XCTAssertEqualObjects(result.tokenCacheItem.resource, @"MyFakeResource");
    XCTAssertEqualObjects(result.tokenCacheItem.clientId, @"27AD83C9-FC05-4A6C-AF01-36EDA42ED18F");
    XCTAssertEqualObjects(result.tokenCacheItem.userInformation.userId, @"myfakeuser@contoso.com");
}

- (void)testResultFromBrokerResponse_whenResponseIsValidWithSpecificTenantAndVTFlagNoClientInfo_shouldReturnResultWithTokenCacheItemWithAndAccessToken
{
    // Not a complete IDToken, but enough to get past the parser. If you're seeing this test fail and have recently
    // changed the idtoken code then this might have to be tweaked.
    NSString* idtokenJSON = @"{\"typ\":\"JWT\",\"aud\":\"c3c7f5e5-7153-44d4-90e6-329686d48d76\",\"iss\":\"https://sts.windows.net/6fd1f5cd-a94c-4335-889b-6c598e6d8048/\",\"iat\":1387224169,\"nbf\":1387224169,\"exp\":1387227769,\"ver\":\"1.0\",\"tid\":\"6fd1f5cd-a94c-4335-889b-6c598e6d8048\",\"oid\":\"53c6acf2-2742-4538-918d-e78257ec8516\",\"upn\":\"myfakeuser@contoso.com\",\"unique_name\":\"myfakeuser@contoso.com\",\"sub\":\"0DxnAlLi12IvGL_dG3dDMk3zp6AQHnjgogyim5AWpSc\",\"family_name\":\"User\",\"given_name\":\"Fake\"}";
    NSDictionary* response = @{
                               @"authority" : @"http://login.windows.net/contoso.com",
                               @"vt" : @"1",
                               @"access_token" : @"MyFakeAccessToken",
                               @"refresh_token" : @"MyFakeRefreshToken",
                               @"resource" : @"MyFakeResource",
                               @"expires_on" : @"1444166530.336707",
                               @"client_id" : @"27AD83C9-FC05-4A6C-AF01-36EDA42ED18F",
                               @"correlation_id" : @"5EF4B8D0-A734-441B-887D-FBB8257C0784",
                               @"id_token" : [idtokenJSON msidBase64UrlEncode],
                               @"user_id" : @"myfakeuser@contoso.com"
                               };
    
    NSError *error = nil;
    MSIDBrokerResponse *brokerResponse = [[MSIDBrokerResponse alloc] initWithDictionary:response error:&error];
    
    XCTAssertNotNil(brokerResponse);
    XCTAssertNil(error);
    
    ADAuthenticationResult *result = [ADAuthenticationResult resultFromBrokerResponse:brokerResponse];
    
    XCTAssertNotNil(result);
    XCTAssertNil(result.error);
    XCTAssertNotNil(result.tokenCacheItem);
    XCTAssertNil(result.tokenCacheItem.userInformation.homeAccountId);
    XCTAssertEqual(result.tokenCacheItem.expiresOn.timeIntervalSince1970, 1444166530);
    XCTAssertEqualObjects(result.tokenCacheItem.accessToken, @"MyFakeAccessToken");
    XCTAssertEqualObjects(result.tokenCacheItem.refreshToken, @"MyFakeRefreshToken");
    XCTAssertEqualObjects(result.tokenCacheItem.resource, @"MyFakeResource");
    XCTAssertEqualObjects(result.tokenCacheItem.clientId, @"27AD83C9-FC05-4A6C-AF01-36EDA42ED18F");
    XCTAssertEqualObjects(result.tokenCacheItem.userInformation.userId, @"myfakeuser@contoso.com");
}

- (void)testResultFromBrokerResponse_whenResponseIsValidFromSpecificTenant_shouldReturnResultWithTokenCacheItemWithNoAccessToken
{
    // Not a complete IDToken, but enough to get past the parser. If you're seeing this test fail and have recently
    // changed the idtoken code then this might have to be tweaked.
    NSString* idtokenJSON = @"{\"typ\":\"JWT\",\"aud\":\"c3c7f5e5-7153-44d4-90e6-329686d48d76\",\"iss\":\"https://sts.windows.net/6fd1f5cd-a94c-4335-889b-6c598e6d8048/\",\"iat\":1387224169,\"nbf\":1387224169,\"exp\":1387227769,\"ver\":\"1.0\",\"tid\":\"6fd1f5cd-a94c-4335-889b-6c598e6d8048\",\"oid\":\"53c6acf2-2742-4538-918d-e78257ec8516\",\"upn\":\"myfakeuser@contoso.com\",\"unique_name\":\"myfakeuser@contoso.com\",\"sub\":\"0DxnAlLi12IvGL_dG3dDMk3zp6AQHnjgogyim5AWpSc\",\"family_name\":\"User\",\"given_name\":\"Fake\"}";
    NSDictionary* response = @{
                               @"authority" : @"http://login.windows.net/common",
                               @"access_token" : @"MyFakeAccessToken",
                               @"refresh_token" : @"MyFakeRefreshToken",
                               @"resource" : @"MyFakeResource",
                               @"expires_on" : @"1444166530.336707",
                               @"client_id" : @"27AD83C9-FC05-4A6C-AF01-36EDA42ED18F",
                               @"correlation_id" : @"5EF4B8D0-A734-441B-887D-FBB8257C0784",
                               @"id_token" : [idtokenJSON msidBase64UrlEncode],
                               @"user_id" : @"myfakeuser@contoso.com",
                               @"client_info" : [self adCreateClientInfo].rawClientInfo
                               };
    
    NSError *error = nil;
    MSIDBrokerResponse *brokerResponse = [[MSIDBrokerResponse alloc] initWithDictionary:response error:&error];
    
    XCTAssertNotNil(brokerResponse);
    XCTAssertNil(error);
    
    ADAuthenticationResult *result = [ADAuthenticationResult resultFromBrokerResponse:brokerResponse];
    
    XCTAssertNotNil(result);
    XCTAssertNil(result.error);
    XCTAssertNotNil(result.tokenCacheItem);
    XCTAssertEqual(result.tokenCacheItem.expiresOn.timeIntervalSince1970, 1444166530);
    XCTAssertEqualObjects(result.tokenCacheItem.accessToken, @"MyFakeAccessToken");
    XCTAssertEqualObjects(result.tokenCacheItem.refreshToken, @"MyFakeRefreshToken");
    XCTAssertEqualObjects(result.tokenCacheItem.resource, @"MyFakeResource");
    XCTAssertEqualObjects(result.tokenCacheItem.clientId, @"27AD83C9-FC05-4A6C-AF01-36EDA42ED18F");
    XCTAssertEqualObjects(result.tokenCacheItem.userInformation.userId, @"myfakeuser@contoso.com");
}

- (void)testResultFromBrokerResponse_whenResponseIsInOldFormat_shouldReturnResultWithParsedValues
{
    // Older versions of the broker send the protocol code in "code", the error details in "error_details" and
    // nothing else. Let's at least try to use all this info.
    NSDictionary *response = @{
                               @"code" : @"could_not_compute",
                               @"error_description" : @"EXTERMINATE!!!!!!",
                               @"correlation_id" : @"5EF4B8D0-A734-441B-887D-FBB8257C0784"
                               };
    
    NSError *error = nil;
    MSIDBrokerResponse *brokerResponse = [[MSIDBrokerResponse alloc] initWithDictionary:response error:&error];
    
    XCTAssertNotNil(brokerResponse);
    XCTAssertNil(error);
    
    ADAuthenticationResult *result = [ADAuthenticationResult resultFromBrokerResponse:brokerResponse];
    
    XCTAssertNotNil(result);
    XCTAssertNotNil(result.error);
    XCTAssertNil(result.tokenCacheItem);
    XCTAssertEqualObjects(result.correlationId, [[NSUUID alloc] initWithUUIDString:@"5EF4B8D0-A734-441B-887D-FBB8257C0784"]);
    XCTAssertEqualObjects(result.error.errorDetails, @"EXTERMINATE!!!!!!");
    XCTAssertEqualObjects(result.error.protocolCode, @"could_not_compute");
    XCTAssertEqual(result.error.code, AD_ERROR_TOKENBROKER_UNKNOWN);
}

- (void)testResultFromBrokerResponse_whenResponseHasFullErrorDetails_shouldReturnResultWithError
{
    NSDictionary *response = @{
                               @"error_code" : @"5",
                               @"protocol_code" : @"wibbly_wobbly",
                               @"error_description" : @"timey wimey",
                               @"correlation_id" : @"5EF4B8D0-A734-441B-887D-FBB8257C0784"
                               };

    NSError *error = nil;
    MSIDBrokerResponse *brokerResponse = [[MSIDBrokerResponse alloc] initWithDictionary:response error:&error];
    
    XCTAssertNotNil(brokerResponse);
    XCTAssertNil(error);
    
    ADAuthenticationResult *result = [ADAuthenticationResult resultFromBrokerResponse:brokerResponse];
    
    XCTAssertNotNil(result);
    XCTAssertNil(result.tokenCacheItem);
    XCTAssertNotNil(result.error);
    XCTAssertEqualObjects(result.error.errorDetails, @"timey wimey");
    XCTAssertEqualObjects(result.error.protocolCode, @"wibbly_wobbly");
    XCTAssertEqual(result.error.code, 5);
    XCTAssertEqualObjects(result.correlationId, [[NSUUID alloc] initWithUUIDString:@"5EF4B8D0-A734-441B-887D-FBB8257C0784"]);
}

- (void)testResultFromBrokerResponse_whenNotNetworkResponse_shouldReturnResultWithError
{
    NSDictionary *response = @{
                               @"error_code" : @"6",
                               @"error_description" : @"I can't find my pants.",
                               @"correlation_id" : @"5EF4B8D0-A734-441B-887D-FBB8257C0784"
                               };
    
    NSError *error = nil;
    MSIDBrokerResponse *brokerResponse = [[MSIDBrokerResponse alloc] initWithDictionary:response error:&error];
    
    XCTAssertNotNil(brokerResponse);
    XCTAssertNil(error);
    
    ADAuthenticationResult* result = [ADAuthenticationResult resultFromBrokerResponse:brokerResponse];
    
    XCTAssertNotNil(result);
    XCTAssertNil(result.tokenCacheItem);
    XCTAssertNotNil(result.error);
    XCTAssertEqualObjects(result.error.errorDetails, @"I can't find my pants.");
    XCTAssertNil(result.error.protocolCode);
    XCTAssertEqual(result.error.code, 6);
    XCTAssertEqualObjects(result.correlationId, [[NSUUID alloc] initWithUUIDString:@"5EF4B8D0-A734-441B-887D-FBB8257C0784"]);
}

@end
