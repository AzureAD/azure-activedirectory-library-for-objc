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
#import "ADAuthenticationContext.h"
#import "ADAuthenticationResult+Internal.h"
#import "ADTokenCacheItem.h"
#import "XCTestCase+TestHelperMethods.h"

@interface ADAuthenticationResultTests : XCTestCase

@end

@implementation ADAuthenticationResultTests

- (void)setUp
{
    [super setUp];
    [self adTestBegin:ADAL_LOG_LEVEL_INFO];
}

- (void)tearDown
{
    [self adTestEnd];
    [super tearDown];
}

//Only static creators and internal initializers are supported. init and new should throw.
- (void) testInitAndNew
{
    XCTAssertThrows([[ADAuthenticationResult alloc] init]);
    XCTAssertThrows([ADAuthenticationResult new]);
}

#define VERIFY_RESULT(_result, _status, _code) { \
    XCTAssertNotNil(_result); \
    XCTAssertEqual(_result.status, _status, "Wrong status"); \
    XCTAssertNotNil(_result.error, "Nil error"); \
    ADAssertLongEquals(_result.error.code, _code); \
    XCTAssertNil(_result.tokenCacheItem.accessToken); \
    XCTAssertNil(_result.tokenCacheItem.accessTokenType); \
    XCTAssertNil(_result.tokenCacheItem.refreshToken); \
    XCTAssertNil(_result.tokenCacheItem.expiresOn); \
    XCTAssertNil(_result.tokenCacheItem.userInformation); \
}

-(void) testResultFromCancellation
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    ADAuthenticationResult* result = [ADAuthenticationResult resultFromCancellation];
    VERIFY_RESULT(result, AD_USER_CANCELLED, AD_ERROR_USER_CANCEL);
}

-(void) testResultFromError
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    ADAuthenticationError* error = [ADAuthenticationError unexpectedInternalError:@"something"];
    ADAuthenticationResult* result = [ADAuthenticationResult resultFromError:error];
    VERIFY_RESULT(result, AD_FAILED, AD_ERROR_UNEXPECTED);
    XCTAssertEqualObjects(result.error, error, "Different error object in the result.");
}

-(void) verifyResult: (ADAuthenticationResult*) resultFromItem
                item: (ADTokenCacheItem*) item
{
    XCTAssertNotNil(resultFromItem);
    XCTAssertEqual(resultFromItem.status, AD_SUCCEEDED, "Result should be success.");
    XCTAssertNil(resultFromItem.error, "Unexpected error object: %@", resultFromItem.error.errorDetails);
    XCTAssertEqual(item.accessTokenType, resultFromItem.tokenCacheItem.accessTokenType);
    XCTAssertEqual(item.accessToken, resultFromItem.tokenCacheItem.accessToken);
    XCTAssertEqual(item.expiresOn, resultFromItem.tokenCacheItem.expiresOn);
    XCTAssertEqual(item.userInformation.tenantId, resultFromItem.tokenCacheItem.userInformation.tenantId);
    ADAssertStringEquals(item.userInformation.userId, resultFromItem.tokenCacheItem.userInformation.userId);
}

- (void)testResultFromtokenCacheItem
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    ADAuthenticationResult* nilItemResult = [ADAuthenticationResult resultFromTokenCacheItem:nil multiResourceRefreshToken:NO correlationId:nil];
    VERIFY_RESULT(nilItemResult, AD_FAILED, AD_ERROR_UNEXPECTED);
    
    [self adSetLogTolerance:ADAL_LOG_LEVEL_INFO];
    ADTokenCacheItem* item = [[ADTokenCacheItem alloc] init];
    item.resource = @"resource";
    item.authority = @"https://login.windows.net/mytennant.com";
    item.clientId = @"clientId";
    item.accessToken = @"accessToken";
    item.accessTokenType = @"tokenType";
    item.refreshToken = @"refreshToken";
    item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:30];
    ADAuthenticationError* error;
    item.userInformation = [ADUserInformation userInformationWithUserId:@"user" error:&error];
    ADAssertNoError;
    
    //Copy the item to ensure that it is not modified withing the method call below:
    ADAuthenticationResult* resultFromValidItem = [ADAuthenticationResult resultFromTokenCacheItem:[item copy] multiResourceRefreshToken:NO correlationId:nil];
    [self verifyResult:resultFromValidItem item:item];
}

- (void)testBrokerResponse
{
    // Not a complete IDToken, but enough to get past the parser. If you're seeing this test fail and have recently
    // changed the idtoken code then this might have to be tweaked.
    NSString* idtokenJSON = @"{\"typ\":\"JWT\",\"aud\":\"c3c7f5e5-7153-44d4-90e6-329686d48d76\",\"iss\":\"https://sts.windows.net/6fd1f5cd-a94c-4335-889b-6c598e6d8048/\",\"iat\":1387224169,\"nbf\":1387224169,\"exp\":1387227769,\"ver\":\"1.0\",\"tid\":\"6fd1f5cd-a94c-4335-889b-6c598e6d8048\",\"oid\":\"53c6acf2-2742-4538-918d-e78257ec8516\",\"upn\":\"myfakeuser@contoso.com\",\"unique_name\":\"myfakeuser@contoso.com\",\"sub\":\"0DxnAlLi12IvGL_dG3dDMk3zp6AQHnjgogyim5AWpSc\",\"family_name\":\"User\",\"given_name\":\"Fake\"}";
    
    NSDictionary* response = @{
                               @"access_token" : @"MyFakeAccessToken",
                               @"refresh_token" : @"MyFakeRefreshToken",
                               @"resource" : @"MyFakeResource",
                               @"expires_on" : @"1444166530.336707",
                               @"client_id" : @"27AD83C9-FC05-4A6C-AF01-36EDA42ED18F",
                               @"correlation_id" : @"5EF4B8D0-A734-441B-887D-FBB8257C0784",
                               @"id_token" : [idtokenJSON adBase64UrlEncode],
                               @"user_id" : @"myfakeuser@contoso.com"
                               };
    ADAuthenticationResult* result = [ADAuthenticationResult resultFromBrokerResponse:response];
    XCTAssertNotNil(result);
    XCTAssertNotNil(result.tokenCacheItem);
    XCTAssertNotNil(result.tokenCacheItem.expiresOn);
    XCTAssertEqual(result.tokenCacheItem.expiresOn.timeIntervalSince1970, 1444166530.336707);
    XCTAssertEqualObjects(result.tokenCacheItem.accessToken, @"MyFakeAccessToken");
    XCTAssertEqualObjects(result.tokenCacheItem.refreshToken, @"MyFakeRefreshToken");
    XCTAssertEqualObjects(result.tokenCacheItem.resource, @"MyFakeResource");
    XCTAssertEqualObjects(result.tokenCacheItem.clientId, @"27AD83C9-FC05-4A6C-AF01-36EDA42ED18F");
    XCTAssertEqualObjects(result.tokenCacheItem.userInformation.userId, @"myfakeuser@contoso.com");
}

- (void)testBrokerOldErrorResponse
{
    // Older versions of the broker send the protocol code in "code", the error details in "error_details" and
    // nothing else. Let's at least try to use all this info.
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    NSDictionary* response = @{
                               @"code" : @"could_not_compute",
                               @"error_description" : @"EXTERMINATE!!!!!!",
                               @"correlation_id" : @"5EF4B8D0-A734-441B-887D-FBB8257C0784"
                               };
    
    ADAuthenticationResult* result = [ADAuthenticationResult resultFromBrokerResponse:response];
    
    XCTAssertNotNil(result);
    XCTAssertNil(result.tokenCacheItem);
    XCTAssertNotNil(result.error);
    XCTAssertEqualObjects(result.error.errorDetails, @"EXTERMINATE!!!!!!");
    XCTAssertEqualObjects(result.error.protocolCode, @"could_not_compute");
    XCTAssertEqualObjects(result.correlationId, [[NSUUID alloc] initWithUUIDString:@"5EF4B8D0-A734-441B-887D-FBB8257C0784"]);
    XCTAssertEqual(result.error.code, AD_ERROR_BROKER_UNKNOWN);
}

- (void)testBrokerFullErrorResponse
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    NSDictionary* response = @{
                               @"error_code" : @"5",
                               @"protocol_code" : @"wibbly_wobbly",
                               @"error_description" : @"timey wimey",
                               @"correlation_id" : @"5EF4B8D0-A734-441B-887D-FBB8257C0784"
                               };

    ADAuthenticationResult* result = [ADAuthenticationResult resultFromBrokerResponse:response];
    
    XCTAssertNotNil(result);
    XCTAssertNil(result.tokenCacheItem);
    XCTAssertNotNil(result.error);
    XCTAssertEqualObjects(result.error.errorDetails, @"timey wimey");
    XCTAssertEqualObjects(result.error.protocolCode, @"wibbly_wobbly");
    XCTAssertEqual(result.error.code, 5);
    XCTAssertEqualObjects(result.correlationId, [[NSUUID alloc] initWithUUIDString:@"5EF4B8D0-A734-441B-887D-FBB8257C0784"]);
}

- (void)testBrokerNonNetworkResponse
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    NSDictionary* response = @{
                               @"error_code" : @"6",
                               @"error_description" : @"I can't find my pants.",
                               @"correlation_id" : @"5EF4B8D0-A734-441B-887D-FBB8257C0784"
                               };
    
    ADAuthenticationResult* result = [ADAuthenticationResult resultFromBrokerResponse:response];
    
    XCTAssertNotNil(result);
    XCTAssertNil(result.tokenCacheItem);
    XCTAssertNotNil(result.error);
    XCTAssertEqualObjects(result.error.errorDetails, @"I can't find my pants.");
    XCTAssertNil(result.error.protocolCode);
    XCTAssertEqual(result.error.code, 6);
    XCTAssertEqualObjects(result.correlationId, [[NSUUID alloc] initWithUUIDString:@"5EF4B8D0-A734-441B-887D-FBB8257C0784"]);
}

@end
