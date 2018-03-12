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

#import "ADAL_Internal.h"
#import "ADLogger.h"
#import "ADErrorCodes.h"
#import "XCTestCase+TestHelperMethods.h"
#import "ADAuthenticationContext.h"
#import "ADAuthenticationSettings.h"
#import <libkern/OSAtomic.h>
#import <Foundation/NSObjCRuntime.h>
#import <objc/runtime.h>
#import "ADTestURLSession.h"
#import "ADTestURLResponse.h"
#import "ADTokenCacheKey.h"
#import "ADTokenCacheItem+Internal.h"
#import "ADUserInformation.h"
#import "ADUserInformation+Internal.h"
#import "NSDictionary+MSIDTestUtil.h"
#import "MSIDTokenCacheItem.h"
#import "MSIDAccessToken.h"
#import "MSIDLegacySingleResourceToken.h"
#import "MSIDRefreshToken.h"
#import "MSIDTestCacheIdentifiers.h"
#import "MSIDTestIdTokenUtil.h"

@implementation XCTestCase (TestHelperMethods)

NSString* const sTestBegin = @"|||TEST_BEGIN|||";
NSString* const sTestEnd = @"|||TEST_END|||";

NSString* const sIdTokenClaims = @"{\"aud\":\"c3c7f5e5-7153-44d4-90e6-329686d48d76\",\"iss\":\"https://sts.windows.net/6fd1f5cd-a94c-4335-889b-6c598e6d8048/\",\"iat\":1387224169,\"nbf\":1387224170,\"exp\":1387227769,\"ver\":\"1.0\",\"tid\":\"6fd1f5cd-a94c-4335-889b-6c598e6d8048\",\"oid\":\"53c6acf2-2742-4538-918d-e78257ec8516\",\"upn\":\"boris@MSOpenTechBV.onmicrosoft.com\",\"unique_name\":\"boris@MSOpenTechBV.onmicrosoft.com\",\"sub\":\"0DxnAlLi12IvGL_dG3dDMk3zp6AQHnjgogyim5AWpSc\",\"family_name\":\"Vidolovv\",\"given_name\":\"Boriss\",\"altsecid\":\"Some Guest id\",\"idp\":\"Fake IDP\",\"email\":\"fake e-mail\"}";
NSString* const sIDTokenHeader = @"{\"typ\":\"JWT\",\"alg\":\"none\"}";

volatile int sAsyncExecuted;//The number of asynchronous callbacks executed.

/* See header for details. */
- (void)adValidateForInvalidArgument:(NSString *)argument
                               error:(ADAuthenticationError *)error
{
    XCTAssertNotNil(argument, "Internal test error: please specify the expected parameter.");
    
    
    XCTAssertNotNil(error, "Error should be raised for the invalid argument '%@'", argument);
    XCTAssertNotNil(error.domain, "Error domain is nil.");
    XCTAssertEqual(error.domain, ADAuthenticationErrorDomain, "Incorrect error domain.");
    XCTAssertNil(error.protocolCode, "The protocol code should not be set. Instead protocolCode ='%@'.", error.protocolCode);
    XCTAssertFalse([NSString msidIsStringNilOrBlank:error.errorDetails], @"Error should have details.");
    BOOL found = [error.errorDetails containsString:argument];
    XCTAssertTrue(found, "The parameter is not specified in the error details. Error details:%@", error.errorDetails);
}

//Parses backwards the log to find the test begin prefix. Returns the beginning
//of the log string if not found:
- (long)indexOfTestBegin:(NSString *)log
{
    NSUInteger index = [log rangeOfString:sTestBegin options:NSBackwardsSearch].location;
    return (index == NSNotFound) ? 0 : index;
}

//String clearing helper method:
- (void)clearString:(NSMutableString *)string
{
    NSRange all = {.location = 0, .length = string.length};
    [string deleteCharactersInRange:all];
}

- (void)adAssertStringEquals:(NSString *)actual
            stringExpression:(NSString *)expression
                    expected:(NSString *)expected
                        file:(const char *)file
                        line:(int)line
{
    if (!actual && !expected)//Both nil, so they are equal
        return;
    if (![expected isEqualToString:actual])
    {
        _XCTFailureHandler(self, YES, file, line, @"Strings.", @"" "The strings are different: '%@' = '%@', expected '%@'", expression, actual, expected);
    }
}

- (ADTokenCacheItem *)adCreateCacheItem
{
    return [self adCreateCacheItem:TEST_USER_ID];
}

//Creates an new item with all of the properties having correct
//values
- (ADTokenCacheItem *)adCreateCacheItem:(NSString *)userId
{
    ADTokenCacheItem* item = [[ADTokenCacheItem alloc] init];
    item.resource = TEST_RESOURCE;
    item.authority = TEST_AUTHORITY;
    item.clientId = TEST_CLIENT_ID;
    item.accessToken = TEST_ACCESS_TOKEN;
    item.refreshToken = TEST_REFRESH_TOKEN;
    //1hr into the future:
    item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:3600];
    if (![NSString msidIsStringNilOrBlank:userId])
    {
        item.userInformation = [self adCreateUserInformation:userId homeUserId:nil];
    }
    item.accessTokenType = TEST_ACCESS_TOKEN_TYPE;
    
    return item;
}

- (ADTokenCacheItem *)adCreateATCacheItem
{
    return [self adCreateATCacheItem:TEST_RESOURCE userId:TEST_USER_ID];
}

- (ADTokenCacheItem *)adCreateATCacheItem:(NSString *)resource
                                   userId:(NSString *)userId
{
    
    ADTokenCacheItem* item = [[ADTokenCacheItem alloc] init];
    item.resource = resource;
    item.authority = TEST_AUTHORITY;
    item.clientId = TEST_CLIENT_ID;
    item.accessToken = TEST_ACCESS_TOKEN;
    item.refreshToken = nil;
    //1hr into the future:
    item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:3600];
    if (![NSString msidIsStringNilOrBlank:userId])
    {
        item.userInformation = [self adCreateUserInformation:userId];
    }
    item.accessTokenType = TEST_ACCESS_TOKEN_TYPE;
    
    return item;
}

- (ADTokenCacheItem *)adCreateMRRTCacheItem
{
    return [self adCreateMRRTCacheItem:TEST_USER_ID familyId:nil];
}

- (ADTokenCacheItem *)adCreateMRRTCacheItem:(NSString *)userId
{
    return [self adCreateMRRTCacheItem:userId familyId:nil];
}

- (ADTokenCacheItem *)adCreateMRRTCacheItem:(NSString *)userId
                                   familyId:(NSString *)foci
{
    // A MRRT item is just a refresh token, it doesn't have a specified resource
    // an expiration time (that we know about) and covers multiple ATs.
    ADTokenCacheItem* item = [[ADTokenCacheItem alloc] init];
    item.authority = TEST_AUTHORITY;
    item.clientId = TEST_CLIENT_ID;
    item.refreshToken = TEST_REFRESH_TOKEN;
    item.familyId = foci;
    if (![NSString msidIsStringNilOrBlank:userId])
    {
        item.userInformation = [self adCreateUserInformation:userId homeUserId:nil];
    }
    
    return item;
}

- (ADTokenCacheItem *)adCreateFRTCacheItem
{
    return [self adCreateFRTCacheItem:@"1" userId:TEST_USER_ID];
}

- (ADTokenCacheItem *)adCreateFRTCacheItem:(NSString *)foci
                                    userId:(NSString *)userId
{
    ADTokenCacheItem* item = [[ADTokenCacheItem alloc] init];
    item.authority = TEST_AUTHORITY;
    // This should match the implementation in +[ADAuthenticationRequest fociClientId:]
    // think long and hard before changing this.
    item.clientId = [NSString stringWithFormat:@"foci-%@", foci];
    item.familyId = foci;
    item.refreshToken = @"family refresh token";
    if (![NSString msidIsStringNilOrBlank:userId])
    {
        item.userInformation = [self adCreateUserInformation:userId];
    }
    
    return item;
}

- (ADTokenCacheKey *)adCreateCacheKey
{
    ADTokenCacheKey* key = [ADTokenCacheKey keyWithAuthority:TEST_AUTHORITY
                                                              resource:TEST_RESOURCE
                                                              clientId:TEST_CLIENT_ID
                                                                 error:nil];
    
    return key;
}

- (ADUserInformation *)adCreateUserInformation:(NSString *)userId
{
    return [self adCreateUserInformation:userId
                                tenantId:@"6fd1f5cd-a94c-4335-889b-6c598e6d8048"
                              homeUserId:nil];
}

- (ADUserInformation *)adCreateUserInformation:(NSString *)userId homeUserId:(NSString *)homeUserId
{
    return [self adCreateUserInformation:userId
                                tenantId:@"6fd1f5cd-a94c-4335-889b-6c598e6d8048"
                              homeUserId:homeUserId];
}

- (ADUserInformation *)adCreateUserInformation:(NSString *)userId
                                      tenantId:(NSString *)tid
                                    homeUserId:(NSString *)homeUserId
{
    NSAssert(userId, @"userId cannot be nil!");
    NSDictionary* part1_claims = @{ @"typ" : @"JWT",
                                    @"alg" : @"none" };
    
    NSDictionary* idtoken_claims = @{ @"aud" : @"c3c7f5e5-7153-44d4-90e6-329686d48d76",
                                      @"iss" : [NSString stringWithFormat:@"https://sts.windows.net/%@", tid],
                                      @"iat" : @"1387224169",
                                      @"nbf" : @"1387224169",
                                      @"exp" : @"1387227769",
                                      @"ver" : @"1.0",
                                      @"tid" : tid,
                                      @"oid" : @"53c6acf2-2742-4538-918d-e78257ec8516",
                                      @"upn" : userId,
                                      @"unique_name" : userId,
                                      @"sub" : @"0DxnAlLi12IvGL_dG3dDMk3zp6AQHnjgogyim5AWpSc",
                                      @"family_name" : @"Cartman",
                                      @"given_name" : @"Eric"
                                      };
    
    NSString* idtoken = [NSString stringWithFormat:@"%@.%@",
                         [NSString msidBase64UrlEncodeData:[NSJSONSerialization dataWithJSONObject:part1_claims options:0 error:nil]],
                         [NSString msidBase64UrlEncodeData:[NSJSONSerialization dataWithJSONObject:idtoken_claims options:0 error:nil]]];
    
    ADUserInformation* userInfo = [ADUserInformation userInformationWithIdToken:idtoken
                                                                     homeUserId:homeUserId
                                                                          error:nil];
    
    // If you're hitting this you might as well fix it before trying to run other tests.
    NSAssert(userInfo, @"Failed to create a userinfo object from a static idtoken. Something must have horribly broke,");
    return userInfo;
}

- (ADTestURLResponse *)adResponseBadRefreshToken:(NSString *)refreshToken
                                       authority:(NSString *)authority
                                        resource:(NSString *)resource
                                        clientId:(NSString *)clientId
                                      oauthError:(NSString *)oauthError
                                   correlationId:(NSUUID *)correlationId
{
    NSString* requestUrlString = [NSString stringWithFormat:@"%@/oauth2/token?x-client-Ver=" ADAL_VERSION_STRING, authority];
    
    NSDictionary *requestHeaders = nil;
    if (correlationId)
    {
        NSMutableDictionary* headers = [[ADTestURLResponse defaultHeaders] mutableCopy];
        headers[@"client-request-id"] = [correlationId UUIDString];
        requestHeaders = headers;
    }
    else
    {
        requestHeaders = [ADTestURLResponse defaultHeaders];
    }
    
    ADTestURLResponse* response =
    [ADTestURLResponse requestURLString:requestUrlString
                         requestHeaders:requestHeaders
                      requestParamsBody:@{ MSID_OAUTH2_GRANT_TYPE : @"refresh_token",
                                           MSID_OAUTH2_REFRESH_TOKEN : refreshToken,
                                           MSID_OAUTH2_RESOURCE : resource,
                                           MSID_OAUTH2_CLIENT_INFO: @"1",
                                           MSID_OAUTH2_CLIENT_ID : clientId }
                      responseURLString:@"https://contoso.com"
                           responseCode:400
                       httpHeaderFields:@{@"x-ms-clitelem" : @"1,7000,7,255.0643,I"}
                       dictionaryAsJSON:@{ MSID_OAUTH2_ERROR : oauthError,
                                           MSID_OAUTH2_ERROR_DESCRIPTION : @"oauth error description"}];
    
    return response;
}

- (ADTestURLResponse *)adDefaultBadRefreshTokenResponseError:(NSString*)oauthError
{
    return [self adResponseBadRefreshToken:TEST_REFRESH_TOKEN
                                 authority:TEST_AUTHORITY
                                  resource:TEST_RESOURCE
                                  clientId:TEST_CLIENT_ID
                                oauthError:oauthError
                             correlationId:TEST_CORRELATION_ID];

}

- (ADTestURLResponse *)adDefaultBadRefreshTokenResponse
{
    return [self adDefaultBadRefreshTokenResponseError:@"invalid_grant"];
}

- (ADTestURLResponse *)adDefaultRefreshResponse:(NSString *)newRefreshToken
                                    accessToken:(NSString *)newAccessToken
{
    return [self adResponseRefreshToken:TEST_REFRESH_TOKEN
                              authority:TEST_AUTHORITY
                               resource:TEST_RESOURCE
                               clientId:TEST_CLIENT_ID
                          correlationId:TEST_CORRELATION_ID
                        newRefreshToken:newRefreshToken
                         newAccessToken:newAccessToken];
}

- (ADTestURLResponse *)adResponseRefreshToken:(NSString *)oldRefreshToken
                                    authority:(NSString *)authority
                                     resource:(NSString *)resource
                                     clientId:(NSString *)clientId
                                correlationId:(NSUUID *)correlationId
                              newRefreshToken:(NSString *)newRefreshToken
                               newAccessToken:(NSString *)newAccessToken
{
    return [self adResponseRefreshToken:oldRefreshToken
                              authority:authority
                               resource:resource
                               clientId:clientId
                         requestHeaders:nil
                          correlationId:correlationId
                        newRefreshToken:newRefreshToken
                         newAccessToken:newAccessToken
                       additionalFields:nil];
}

- (ADTestURLResponse *)adResponseRefreshToken:(NSString *)oldRefreshToken
                                    authority:(NSString *)authority
                                     resource:(NSString *)resource
                                     clientId:(NSString *)clientId
                                correlationId:(NSUUID *)correlationId
                              newRefreshToken:(NSString *)newRefreshToken
                               newAccessToken:(NSString *)newAccessToken
                             additionalFields:(NSDictionary *)additionalFields
{
    return [self adResponseRefreshToken:oldRefreshToken
                              authority:authority
                               resource:resource
                               clientId:clientId
                         requestHeaders:nil
                          correlationId:correlationId
                        newRefreshToken:newRefreshToken
                         newAccessToken:newAccessToken
                       additionalFields:additionalFields];
}

- (ADTestURLResponse *)adResponseRefreshToken:(NSString *)oldRefreshToken
                                    authority:(NSString *)authority
                                     resource:(NSString *)resource
                                     clientId:(NSString *)clientId
                               requestHeaders:(NSDictionary *)requestHeaders
                                correlationId:(NSUUID *)correlationId
                              newRefreshToken:(NSString *)newRefreshToken
                               newAccessToken:(NSString *)newAccessToken
                             additionalFields:(NSDictionary *)additionalFields
{
    return [self adResponseRefreshToken:oldRefreshToken
                              authority:authority
                               resource:resource
                               clientId:clientId
                         requestHeaders:requestHeaders
                          correlationId:correlationId
                        newRefreshToken:newRefreshToken
                         newAccessToken:newAccessToken
                       additionalFields:additionalFields
                        responseHeaders:nil];
}

- (ADTestURLResponse *)adResponseRefreshToken:(NSString *)oldRefreshToken
                                    authority:(NSString *)authority
                                     resource:(NSString *)resource
                                     clientId:(NSString *)clientId
                               requestHeaders:(NSDictionary *)requestHeaders
                                correlationId:(NSUUID *)correlationId
                              newRefreshToken:(NSString *)newRefreshToken
                               newAccessToken:(NSString *)newAccessToken
                             additionalFields:(NSDictionary *)additionalFields
                              responseHeaders:(NSDictionary *)responseHeaders
{
    NSDictionary* jsonBody = @{ MSID_OAUTH2_REFRESH_TOKEN : newRefreshToken,
                                MSID_OAUTH2_ACCESS_TOKEN : newAccessToken,
                                MSID_OAUTH2_RESOURCE : resource };
    
    if (additionalFields)
    {
        NSMutableDictionary* combinedDictionary = [NSMutableDictionary dictionaryWithDictionary:jsonBody];
        [combinedDictionary addEntriesFromDictionary:additionalFields];
        jsonBody = combinedDictionary;
    }
    
    return [self adResponseRefreshToken:oldRefreshToken
                              authority:authority
                               resource:resource
                               clientId:clientId
                         requestHeaders:requestHeaders
                          correlationId:correlationId
                           responseCode:400
                        responseHeaders:responseHeaders
                           responseJson:jsonBody];
}

- (ADTestURLResponse *)adDefaultRefreshReponseCode:(NSInteger)responseCode
                                   responseHeaders:(NSDictionary *)responseHeaders
                                      responseJson:(NSDictionary *)responseJson
{
    return [self adResponseRefreshToken:TEST_REFRESH_TOKEN
                              authority:TEST_AUTHORITY
                               resource:TEST_RESOURCE
                               clientId:TEST_CLIENT_ID
                         requestHeaders:nil
                          correlationId:TEST_CORRELATION_ID
                           responseCode:responseCode
                        responseHeaders:responseHeaders
                           responseJson:responseJson];
}

- (ADTestURLResponse *)adResponseRefreshToken:(NSString *)oldRefreshToken
                                    authority:(NSString *)authority
                                     resource:(NSString *)resource
                                     clientId:(NSString *)clientId
                               requestHeaders:(NSDictionary *)requestHeaders
                                correlationId:(NSUUID *)correlationId
                                 responseCode:(NSInteger)responseCode
                              responseHeaders:(NSDictionary *)responseHeaders
                                 responseJson:(NSDictionary *)responseJson

{
    NSString* requestUrlString = [NSString stringWithFormat:@"%@/oauth2/token?x-client-Ver=" ADAL_VERSION_STRING, authority];
    
    NSMutableDictionary* headers = [[ADTestURLResponse defaultHeaders] mutableCopy];
    headers[@"client-request-id"] = [correlationId UUIDString];
    if (requestHeaders)
    {
        [headers addEntriesFromDictionary:requestHeaders];
    }

    ADTestURLResponse* response =
    [ADTestURLResponse requestURLString:requestUrlString
                         requestHeaders:headers
                      requestParamsBody:@{ MSID_OAUTH2_GRANT_TYPE : @"refresh_token",
                                           MSID_OAUTH2_REFRESH_TOKEN : oldRefreshToken,
                                           MSID_OAUTH2_RESOURCE : resource,
                                           MSID_OAUTH2_CLIENT_INFO: @"1",
                                           MSID_OAUTH2_CLIENT_ID : clientId }
                      responseURLString:@"https://contoso.com"
                           responseCode:responseCode
                       httpHeaderFields:responseHeaders ? responseHeaders : @{}
                       dictionaryAsJSON:responseJson];
    
    return response;
}

- (ADTestURLResponse *)adResponseAuthCode:(NSString *)authCode
                                authority:(NSString *)authority
                            correlationId:(NSUUID *)correlationId
{
    NSString* requestUrlString = [NSString stringWithFormat:@"%@/oauth2/token?x-client-Ver=" ADAL_VERSION_STRING, authority];
    
    NSMutableDictionary* headers = [[ADTestURLResponse defaultHeaders] mutableCopy];
    headers[@"client-request-id"] = [correlationId UUIDString];
    
    ADTestURLResponse* response =
    [ADTestURLResponse requestURLString:requestUrlString
                         requestHeaders:headers
                      requestParamsBody:@{ MSID_OAUTH2_GRANT_TYPE : MSID_OAUTH2_AUTHORIZATION_CODE,
                                           MSID_OAUTH2_CODE : authCode,
                                           MSID_OAUTH2_CLIENT_ID : TEST_CLIENT_ID,
                                           MSID_OAUTH2_CLIENT_INFO: @"1",
                                           MSID_OAUTH2_REDIRECT_URI : TEST_REDIRECT_URL_STRING }
                      responseURLString:@"https://contoso.com"
                           responseCode:200
                       httpHeaderFields:@{}
                       dictionaryAsJSON:@{ @"refresh_token" : TEST_REFRESH_TOKEN,
                                           @"access_token" : TEST_ACCESS_TOKEN,
                                           @"expires_in" : @"3600",
                                           @"resource" : TEST_RESOURCE,
                                           @"id_token" : [self adCreateUserInformation:TEST_USER_ID].rawIdToken }];
    
    return response;
}

- (MSIDTokenCacheItem *)adCreateAccessMSIDTokenCacheItem
{
    MSIDTokenCacheItem *tokenCacheItem = [MSIDTokenCacheItem new];
    tokenCacheItem.accessToken = DEFAULT_TEST_ACCESS_TOKEN;
    tokenCacheItem.refreshToken = nil;
    tokenCacheItem.idToken = [MSIDTestIdTokenUtil idTokenWithName:DEFAULT_TEST_ID_TOKEN_NAME
                                                              upn:DEFAULT_TEST_ID_TOKEN_USERNAME
                                                         tenantId:DEFAULT_TEST_UTID];
    tokenCacheItem.expiresOn = [NSDate dateWithTimeIntervalSince1970:1500000000];
    tokenCacheItem.cachedAt = nil;
    tokenCacheItem.familyId = nil;
    tokenCacheItem.clientInfo = [self adCreateClientInfo];
    tokenCacheItem.additionalInfo = @{@"key2" : @"value2"};
    tokenCacheItem.target = DEFAULT_TEST_RESOURCE;
    tokenCacheItem.authority = [[NSURL alloc] initWithString:DEFAULT_TEST_AUTHORITY];
    tokenCacheItem.clientId = DEFAULT_TEST_CLIENT_ID;
    tokenCacheItem.tokenType = MSIDTokenTypeAccessToken;
    tokenCacheItem.username = nil;
    
    return tokenCacheItem;
}

- (MSIDTokenCacheItem *)adCreateRefreshMSIDTokenCacheItem
{
    MSIDTokenCacheItem *tokenCacheItem = [MSIDTokenCacheItem new];
    
    tokenCacheItem.accessToken = nil;
    tokenCacheItem.refreshToken = DEFAULT_TEST_REFRESH_TOKEN;
    tokenCacheItem.idToken = [MSIDTestIdTokenUtil idTokenWithName:DEFAULT_TEST_ID_TOKEN_NAME
                                                              upn:DEFAULT_TEST_ID_TOKEN_USERNAME
                                                         tenantId:DEFAULT_TEST_UTID];
    tokenCacheItem.expiresOn = nil;
    tokenCacheItem.cachedAt = nil;
    tokenCacheItem.familyId = @"familyId value";
    tokenCacheItem.clientInfo = [self adCreateClientInfo];
    tokenCacheItem.additionalInfo = @{@"key2" : @"value2"};
    tokenCacheItem.target = nil;
    tokenCacheItem.authority = [[NSURL alloc] initWithString:DEFAULT_TEST_AUTHORITY];
    tokenCacheItem.clientId = DEFAULT_TEST_CLIENT_ID;
    tokenCacheItem.tokenType = MSIDTokenTypeRefreshToken;
    tokenCacheItem.username = nil;
    
    return tokenCacheItem;
}

- (MSIDTokenCacheItem *)adCreateLegacySingleResourceMSIDTokenCacheItem
{
    MSIDTokenCacheItem *tokenCacheItem = [MSIDTokenCacheItem new];
    
    tokenCacheItem.accessToken = DEFAULT_TEST_ACCESS_TOKEN;
    tokenCacheItem.refreshToken = DEFAULT_TEST_REFRESH_TOKEN;
    tokenCacheItem.idToken = [MSIDTestIdTokenUtil idTokenWithName:DEFAULT_TEST_ID_TOKEN_NAME
                                                              upn:DEFAULT_TEST_ID_TOKEN_USERNAME
                                                         tenantId:DEFAULT_TEST_UTID];
    tokenCacheItem.expiresOn = [NSDate dateWithTimeIntervalSince1970:1500000000];
    tokenCacheItem.cachedAt = nil;
    tokenCacheItem.familyId = @"familyId value";
    tokenCacheItem.clientInfo = [self adCreateClientInfo];
    tokenCacheItem.additionalInfo = @{@"key2" : @"value2"};
    tokenCacheItem.target = DEFAULT_TEST_RESOURCE;
    tokenCacheItem.authority = [[NSURL alloc] initWithString:DEFAULT_TEST_AUTHORITY];
    tokenCacheItem.clientId = DEFAULT_TEST_CLIENT_ID;
    tokenCacheItem.tokenType = MSIDTokenTypeLegacySingleResourceToken;
    tokenCacheItem.username = nil;
    
    return tokenCacheItem;
}

- (MSIDClientInfo *)adCreateClientInfo
{
    NSString *clientInfoJsonString = @"{\"uid\":\"28f3807a-4fb0-45f2-a44a-236aa0cb3f97\",\"utid\":\"0284f963-1d72-4363-5e3a-5705c5b0f031\"}";
    
    MSIDClientInfo *clientInfo = [[MSIDClientInfo alloc] initWithRawClientInfo:[clientInfoJsonString msidBase64UrlEncode] error:nil];
    
    assert(clientInfo);
    
    return clientInfo;
}

- (MSIDAccessToken *)adCreateAccessToken
{
    MSIDAccessToken *accessToken = [MSIDAccessToken new];
    [self fillBaseToken:accessToken];
    [self fillAccessToken:accessToken];
    
    return accessToken;
}

- (MSIDRefreshToken *)adCreateRefreshToken
{
    MSIDRefreshToken *refreshToken = [MSIDRefreshToken new];
    [self fillBaseToken:refreshToken];
    
    [refreshToken setValue:@"refresh token" forKey:@"refreshToken"];
    [refreshToken setValue:@"family Id" forKey:@"familyId"];
    NSString *rawIdToken = [self adCreateUserInformation:TEST_USER_ID].rawIdToken;
    [refreshToken setValue:rawIdToken forKey:@"idToken"];
    
    return refreshToken;
}

- (MSIDLegacySingleResourceToken *)adCreateLegacySingleResourceToken
{
    MSIDLegacySingleResourceToken *legacySingleResourceToken = [MSIDLegacySingleResourceToken new];
    [self fillBaseToken:legacySingleResourceToken];
    [self fillAccessToken:legacySingleResourceToken];
    
    [legacySingleResourceToken setValue:@"refresh token" forKey:@"refreshToken"];
    NSString *rawIdToken = [self adCreateUserInformation:TEST_USER_ID].rawIdToken;
    [legacySingleResourceToken setValue:rawIdToken forKey:@"idToken"];
    
    return legacySingleResourceToken;
}

#pragma mark - Private

- (void)fillBaseToken:(MSIDBaseToken *)baseToken
{
    [baseToken setValue:[[NSURL alloc] initWithString:TEST_AUTHORITY] forKey:@"authority"];
    [baseToken setValue:TEST_CLIENT_ID forKey:@"clientId"];
    [baseToken setValue:@"unique User Id" forKey:@"uniqueUserId"];
    MSIDClientInfo *clientInfo = [self adCreateClientInfo];
    [baseToken setValue:clientInfo forKey:@"clientInfo"];
    [baseToken setValue:@{@"key2" : @"value2"} forKey:@"additionaServerlInfo"];
    [baseToken setValue:@"Eric Cartman" forKey:@"username"];
}

- (void)fillAccessToken:(MSIDAccessToken *)accessToken
{
    [accessToken setValue:[NSDate dateWithTimeIntervalSince1970:1500000000] forKey:@"expiresOn"];
    [accessToken setValue:[NSDate dateWithTimeIntervalSince1970:1100000000] forKey:@"cachedAt"];
    [accessToken setValue:@"access token" forKey:@"accessToken"];
    [accessToken setValue:@"Bearer" forKey:@"accessTokenType"];
    NSString *rawIdToken = [self adCreateUserInformation:TEST_USER_ID].rawIdToken;
    [accessToken setValue:rawIdToken forKey:@"idToken"];
    [accessToken setValue:TEST_RESOURCE forKey:@"target"];
}

@end
