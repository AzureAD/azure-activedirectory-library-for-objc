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
#import "ADAuthenticationError.h"
#import "ADAL_Internal.h"
#import "ADTelemetry.h"
#import "ADTestConstants.h"

#define ADTAssertContains(_str, _contains) XCTAssertTrue([_str containsString:_contains], "%@ does not contain \"%@\"", _str, _contains)

@class ADTokenCacheItem;
@class ADUserInformation;
@class ADTokenCacheKey;
@class ADTestURLResponse;
@class MSIDLegacyTokenCacheItem;
@class MSIDClientInfo;
@class MSIDLegacyAccessToken;
@class MSIDLegacyRefreshToken;
@class MSIDLegacySingleResourceToken;
@class MSIDConfiguration;
@class MSIDAADV2TokenResponse;

@interface XCTestCase (HelperMethods)

- (void)adAssertStringEquals:(NSString *)actual
            stringExpression:(NSString *)expression
                    expected:(NSString *)expected
                        file:(const char *)file
                        line:(int)line;

- (ADTestURLResponse *)adResponseBadRefreshToken:(NSString *)refreshToken
                                       authority:(NSString *)authority
                                        resource:(NSString *)resource
                                        clientId:(NSString *)clientId
                                      oauthError:(NSString *)oauthError
                                   correlationId:(NSUUID *)correlationId;
- (ADTestURLResponse *)adDefaultBadRefreshTokenResponseError:(NSString*)oauthError;
- (ADTestURLResponse *)adDefaultBadRefreshTokenResponse;

- (ADTestURLResponse *)adDefaultRefreshResponse:(NSString *)newRefreshToken
                                    accessToken:(NSString *)newAccessToken
                                     newIDToken:(NSString *)newIDToken;

- (ADTestURLResponse *)adResponseRefreshToken:(NSString *)oldRefreshToken
                                    authority:(NSString *)authority
                                     resource:(NSString *)resource
                                     clientId:(NSString *)clientId
                                correlationId:(NSUUID *)correlationId
                              newRefreshToken:(NSString *)newRefreshToken
                               newAccessToken:(NSString *)newAccessToken
                                   newIDToken:(NSString *)newIDToken;

- (ADTestURLResponse *)adResponseRefreshToken:(NSString *)oldRefreshToken
                                    authority:(NSString *)authority
                              requestResource:(NSString *)requestResource
                             responseResource:(NSString *)responseResource
                                     clientId:(NSString *)clientId
                                correlationId:(NSUUID *)correlationId
                              newRefreshToken:(NSString *)newRefreshToken
                               newAccessToken:(NSString *)newAccessToken
                                   newIDToken:(NSString *)newIDToken;

/*! Used for constructing a refresh token response with additional information in the JSON body */
- (ADTestURLResponse *)adResponseRefreshToken:(NSString *)oldRefreshToken
                                    authority:(NSString *)authority
                                     resource:(NSString *)resource
                                     clientId:(NSString *)clientId
                                correlationId:(NSUUID *)correlationId
                              newRefreshToken:(NSString *)newRefreshToken
                               newAccessToken:(NSString *)newAccessToken
                                   newIDToken:(NSString *)newIDToken
                             additionalFields:(NSDictionary *)additionalFields;


- (ADTestURLResponse *)adResponseRefreshToken:(NSString *)oldRefreshToken
                                    authority:(NSString *)authority
                                     resource:(NSString *)resource
                                     clientId:(NSString *)clientId
                               requestHeaders:(NSDictionary *)requestHeaders
                                correlationId:(NSUUID *)correlationId
                              newRefreshToken:(NSString *)newRefreshToken
                               newAccessToken:(NSString *)newAccessToken
                                   newIDToken:(NSString *)newIDToken
                             additionalFields:(NSDictionary *)additionalFields;

- (ADTestURLResponse *)adResponseRefreshToken:(NSString *)oldRefreshToken
                                    authority:(NSString *)authority
                              requestResource:(NSString *)requestResource
                             responseResource:(NSString *)responseResource
                                     clientId:(NSString *)clientId
                               requestHeaders:(NSDictionary *)requestHeaders
                                correlationId:(NSUUID *)correlationId
                              newRefreshToken:(NSString *)newRefreshToken
                               newAccessToken:(NSString *)newAccessToken
                                   newIDToken:(NSString *)newIDToken
                             additionalFields:(NSDictionary *)additionalFields
                              responseHeaders:(NSDictionary *)responseHeaders;

/*! Used for constructing a response with the provided refresh token parameters */
- (ADTestURLResponse *)adResponseRefreshToken:(NSString *)oldRefreshToken
                                    authority:(NSString *)authority
                                     resource:(NSString *)resource
                                     clientId:(NSString *)clientId
                                correlationId:(NSUUID *)correlationId
                                 responseCode:(NSInteger)responseCode
                              responseHeaders:(NSDictionary *)responseHeaders
                                 responseJson:(NSDictionary *)responseJson;


- (ADTestURLResponse *)adResponseRefreshToken:(NSString *)oldRefreshToken
                                    authority:(NSString *)authority
                                     resource:(NSString *)resource
                                     clientId:(NSString *)clientId
                               requestHeaders:(NSDictionary *)requestHeaders
                                correlationId:(NSUUID *)correlationId
                                 responseCode:(NSInteger)responseCode
                              responseHeaders:(NSDictionary *)responseHeaders
                                 responseJson:(NSDictionary *)responseJson
                             useOpenidConnect:(BOOL)useOpenidConnect;

- (ADTestURLResponse *)adResponseAuthCode:(NSString *)authCode
                                authority:(NSString *)authority
                            correlationId:(NSUUID *)correlationId;

- (NSString *)adDefaultIDToken;

/*! Used for constructing a response with a specific HTTP code and HTTP headers 
    to a default refresh token request */
- (ADTestURLResponse *)adDefaultRefreshReponseCode:(NSInteger)responseCode
                                   responseHeaders:(NSDictionary *)responseHeaders
                                      responseJson:(NSDictionary *)responseJson;

//Creates a new item with all of the properties having correct values
- (ADTokenCacheItem *)adCreateCacheItem;
- (ADTokenCacheItem *)adCreateCacheItem:(NSString*)userId;
- (ADTokenCacheItem *)adCreateATCacheItem;
- (ADTokenCacheItem *)adCreateATCacheItem:(NSString *)resource
                                   userId:(NSString *)userId;

- (ADTokenCacheItem *)adCreateMRRTCacheItem;
- (ADTokenCacheItem *)adCreateMRRTCacheItem:(NSString *)userId;
- (ADTokenCacheItem *)adCreateMRRTCacheItem:(NSString *)userId
                                   familyId:(NSString *)familyId;
- (ADTokenCacheItem *)adCreateFRTCacheItem;
- (ADTokenCacheItem *)adCreateFRTCacheItem:(NSString *)familyId
                                    userId:(NSString *)userId;
- (ADTokenCacheKey *)adCreateCacheKey;

//Creates a sample user information object
- (ADUserInformation *)adCreateUserInformation:(NSString *)userId;
- (ADUserInformation *)adCreateUserInformation:(NSString *)userId homeAccountId:(NSString *)homeAccountId;
- (ADUserInformation *)adCreateUserInformation:(NSString *)userId tenantId:(NSString *)tid homeAccountId:(NSString *)homeAccountId;

- (MSIDLegacyTokenCacheItem *)adCreateAccessMSIDTokenCacheItem;
- (MSIDLegacyTokenCacheItem *)adCreateRefreshMSIDTokenCacheItem;
- (MSIDLegacyTokenCacheItem *)adCreateLegacySingleResourceMSIDTokenCacheItem;

- (MSIDClientInfo *)adCreateClientInfo;

- (MSIDLegacyAccessToken *)adCreateAccessToken;
- (MSIDLegacyRefreshToken *)adCreateRefreshToken;
- (MSIDLegacySingleResourceToken *)adCreateLegacySingleResourceToken;

- (MSIDConfiguration *)adCreateV2DefaultConfiguration;
- (MSIDAADV2TokenResponse *)adCreateV2TokenResponse;
- (NSString *)adCreateV2IdToken;

@end

//Fixes the issue with XCTAssertEqual not comparing int and long values
//Usage: ADAssertLongEquals(5, [self calculateFive]);
#define ADAssertLongEquals(CONST, EXPR) XCTAssertEqual((long)CONST, (long)EXPR)

#define ADAssertThrowsArgument(EXP) \
{ \
    XCTAssertThrowsSpecificNamed((EXP), NSException, NSInvalidArgumentException, "Exception expected for %s", #EXP); \
}

//Usage: ADAssertStringEquals(resultString, "Blah");
#define ADAssertStringEquals(actualParam, expectedParam) \
{ \
    [self adAssertStringEquals:actualParam \
              stringExpression:@"" #actualParam \
                      expected:expectedParam \
                           file:__FILE__ \
                           line:__LINE__]; \
}

//Fixes the problem with the test framework not able to compare dates:
#define ADAssertDateEquals(actualParam, expectedParam) XCTAssertTrue([expectedParam compare:actualParam] == NSOrderedSame)


//Verifes that "error" local variable is nil. If not prints the error
#define ADAssertNoError XCTAssertNil(error, "Unexpected error occurred: %@", error.errorDetails)

