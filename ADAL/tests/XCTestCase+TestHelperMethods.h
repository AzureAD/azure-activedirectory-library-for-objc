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

@interface XCTestCase (HelperMethods)

+ (ADUserInformation *)adCreateUserInformation:(NSString *)userId
                                      tenantId:(NSString *)tid;

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
                                    accessToken:(NSString *)newAccessToken;

- (ADTestURLResponse *)adResponseRefreshToken:(NSString *)oldRefreshToken
                                    authority:(NSString *)authority
                                     resource:(NSString *)resource
                                     clientId:(NSString *)clientId
                                correlationId:(NSUUID *)correlationId
                              newRefreshToken:(NSString *)newRefreshToken
                               newAccessToken:(NSString *)newAccessToken;

/*! Used for constructing a refresh token response with additional information in the JSON body */
- (ADTestURLResponse *)adResponseRefreshToken:(NSString *)oldRefreshToken
                                    authority:(NSString *)authority
                                     resource:(NSString *)resource
                                     clientId:(NSString *)clientId
                                correlationId:(NSUUID *)correlationId
                              newRefreshToken:(NSString *)newRefreshToken
                               newAccessToken:(NSString *)newAccessToken
                             additionalFields:(NSDictionary *)additionalFields;


- (ADTestURLResponse *)adResponseRefreshToken:(NSString *)oldRefreshToken
                                    authority:(NSString *)authority
                                     resource:(NSString *)resource
                                     clientId:(NSString *)clientId
                               requestHeaders:(NSDictionary *)requestHeaders
                                correlationId:(NSUUID *)correlationId
                              newRefreshToken:(NSString *)newRefreshToken
                               newAccessToken:(NSString *)newAccessToken
                             additionalFields:(NSDictionary *)additionalFields;

- (ADTestURLResponse *)adResponseRefreshToken:(NSString *)oldRefreshToken
                                    authority:(NSString *)authority
                                     resource:(NSString *)resource
                                     clientId:(NSString *)clientId
                               requestHeaders:(NSDictionary *)requestHeaders
                                correlationId:(NSUUID *)correlationId
                              newRefreshToken:(NSString *)newRefreshToken
                               newAccessToken:(NSString *)newAccessToken
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
                                 responseJson:(NSDictionary *)responseJson;

- (ADTestURLResponse *)adResponseAuthCode:(NSString *)authCode
                                authority:(NSString *)authority
                            correlationId:(NSUUID *)correlationId;

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

+ (ADTokenCacheItem *)adCreateMRRTCacheItem;
- (ADTokenCacheItem *)adCreateMRRTCacheItem;
- (ADTokenCacheItem *)adCreateMRRTCacheItem:(NSString *)userId;
- (ADTokenCacheItem *)adCreateMRRTCacheItem:(NSString *)userId
                                   familyId:(NSString *)familyId;
- (ADTokenCacheItem *)adCreateFRTCacheItem;
- (ADTokenCacheItem *)adCreateFRTCacheItem:(NSString *)familyId
                                    userId:(NSString *)userId;
- (ADTokenCacheKey *)adCreateCacheKey;

//Creates a sample user information object
- (ADUserInformation *)adCreateUserInformation:(NSString*)userId;

//Mocks ADEnrollmentGateway
- (void) mockADEnrollmentGateway;
- (void) revertADEnrollmentGatewayMock;

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

// Defines test JSON for IntuneEnrollmentIDs
#define IntuneTestJSON [NSString stringWithFormat: \
                            @"{\"enrollment_ids\": [\n" \
                                    "{\n" \
                                        "\"tid\" : \"fda5d5d9-17c3-4c29-9cf9-a27c3d3f03e1\",\n" \
                                        "\"oid\" : \"d3444455-mike-4271-b6ea-e499cc0cab46\",\n" \
                                        "\"unique_account_id\" : \"60406d5d-mike-41e1-aa70-e97501076a22\",\n" \
                                        "\"user_id\" : \"mike@contoso.com\",\n" \
                                        "\"enrollment_id\" : \"adf79e3f-mike-454d-9f0f-2299e76dbfd5\"\n" \
                                    "},\n" \
                                    "{\n" \
                                        "\"tid\" : \"fda5d5d9-17c3-4c29-9cf9-a27c3d3f03e1\",\n" \
                                        "\"oid\" : \"6eec576f-dave-416a-9c4a-536b178a194a\",\n" \
                                        "\"unique_account_id\" : \"1e4dd613-dave-4527-b50a-97aca38b57ba\",\n" \
                                        "\"user_id\" : \"dave@contoso.com\",\n" \
                                        "\"enrollment_id\" : \"64d0557f-dave-4193-b630-8491ffd3b180\"\n" \
                                    "},\n" \
                                "]\n" \
                            "}"];

