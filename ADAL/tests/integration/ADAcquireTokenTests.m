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
#import "ADAL_Internal.h"
#import "ADALAuthenticationContext+Internal.h"
#import "XCTestCase+TestHelperMethods.h"
#import <libkern/OSAtomic.h>
#import "ADALWebRequest.h"
#import "ADTestURLSession.h"
#import "ADTestURLResponse.h"
#import "ADALAuthenticationSettings.h"
#import "ADALTokenCacheItem+Internal.h"
#import "ADALTokenCacheDataSource.h"
#import "ADALTelemetryTestDispatcher.h"
#import "ADALUserIdentifier.h"
#import "ADALAuthorityValidation.h"
#import "MSIDLegacyTokenCacheAccessor.h"
#import "MSIDLegacyTokenCacheAccessor.h"
#import "MSIDDefaultTokenCacheAccessor.h"
#import "ADALAuthenticationContext+TestUtil.h"
#import "MSIDAADV2TokenResponse.h"
#import "MSIDAADV2Oauth2Factory.h"
#import "ADALTokenCacheKey.h"
#import "MSIDBaseToken.h"
#import "MSIDAADV1Oauth2Factory.h"
#import "MSIDRefreshToken.h"
#import "ADALEnrollmentGateway+TestUtil.h"

#import "ADTestWebAuthController.h"

#if TARGET_OS_IPHONE
#import "MSIDKeychainTokenCache+MSIDTestsUtil.h"
#import "MSIDKeychainTokenCache.h"
#import "ADLegacyKeychainTokenCache.h"
#else
#import "ADALTokenCache+Internal.h"
#endif
#import "ADALUserInformation.h"
#import "MSIDWebAADAuthResponse.h"
#import "ADALEnrollmentGateway+UnitTests.h"
#import "ADTestWebAuthController.h"

const int sAsyncContextTimeout = 10;

@interface ADAcquireTokenTests : ADTestCase

@property (nonatomic) MSIDLegacyTokenCacheAccessor *tokenCache;
@property (nonatomic) MSIDDefaultTokenCacheAccessor *msalTokenCache;
@property (nonatomic) id<ADALTokenCacheDataSource> cacheDataSource;

@end

@implementation ADAcquireTokenTests

- (void)setUp
{
    [super setUp];

    [[ADALAuthorityValidation sharedInstance] addInvalidAuthority:TEST_AUTHORITY];
    
#if TARGET_OS_IPHONE
    [MSIDKeychainTokenCache reset];

    self.cacheDataSource = ADLegacyKeychainTokenCache.defaultKeychainCache;

    MSIDDefaultTokenCacheAccessor *defaultTokenCacheAccessor = [[MSIDDefaultTokenCacheAccessor alloc] initWithDataSource:MSIDKeychainTokenCache.defaultKeychainCache otherCacheAccessors:nil factory:[MSIDAADV2Oauth2Factory new]];

    MSIDLegacyTokenCacheAccessor *legacyTokenCacheAccessor = [[MSIDLegacyTokenCacheAccessor alloc] initWithDataSource:MSIDKeychainTokenCache.defaultKeychainCache otherCacheAccessors:@[defaultTokenCacheAccessor] factory:[MSIDAADV1Oauth2Factory new]];

    self.tokenCache = legacyTokenCacheAccessor;
    self.msalTokenCache = defaultTokenCacheAccessor;
#else
    ADALTokenCache *adalTokenCache = [ADALTokenCache new];
    self.cacheDataSource = adalTokenCache;
    self.tokenCache = [[MSIDLegacyTokenCacheAccessor alloc] initWithDataSource:ADALTokenCache.macTokenCache otherCacheAccessors:nil factory:[MSIDAADV1Oauth2Factory new]];
#endif
}

- (void)tearDown
{
    [super tearDown];

    [ADALTelemetry sharedInstance].piiEnabled = NO;
    [ADALEnrollmentGateway setEnrollmentIdsWithJsonBlob:nil];
    [ADALEnrollmentGateway setIntuneMAMResourceWithJsonBlob:nil];
}

- (ADALAuthenticationContext *)getTestAuthenticationContext
{
    ADALAuthenticationContext* context =
        [[ADALAuthenticationContext alloc] initWithAuthority:TEST_AUTHORITY
                                         validateAuthority:NO
                                                     error:nil];
    context.tokenCache = self.tokenCache;

    NSAssert(context, @"If this is failing for whatever reason you should probably fix it before trying to run tests.");

    [context setCorrelationId:TEST_CORRELATION_ID];

    return context;
}

- (void)testBadCompletionBlock
{
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    ADAuthenticationCallback callback = nil;
    ADAssertThrowsArgument([context acquireTokenWithResource:TEST_RESOURCE clientId:TEST_CLIENT_ID redirectUri:TEST_REDIRECT_URL completionBlock:callback]);
}

- (void)testBadResource
{
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireToken without resource should return error."];
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    NSString *resource = nil;
    [context acquireTokenWithResource:resource
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                      completionBlock:^(ADALAuthenticationResult *result)
    {
        XCTAssertNotNil(result);
        XCTAssertEqual(result.status, AD_FAILED);
        XCTAssertNotNil(result.error);
        XCTAssertEqual(result.error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);
        ADTAssertContains(result.error.errorDetails, @"resource");

        [expectation fulfill];
    }];

    [self waitForExpectations:@[expectation] timeout:1];

    expectation = [self expectationWithDescription:@"acquireToken with invalid resource should return error."];
    [context acquireTokenWithResource:@"   "
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                      completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);
         ADTAssertContains(result.error.errorDetails, @"resource");

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testBadClientId
{
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];

    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireToken without clientId should return error."];
    NSString *clientId = nil;
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:clientId
                          redirectUri:TEST_REDIRECT_URL
                      completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);
         XCTAssertNil(result.authority);
         ADTAssertContains(result.error.errorDetails, @"clientId");

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];

    expectation = [self expectationWithDescription:@"acquireToken with invalid clientId should return error."];
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:@"    "
                          redirectUri:TEST_REDIRECT_URL
                      completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);
         XCTAssertNil(result.authority);
         ADTAssertContains(result.error.errorDetails, @"clientId");

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testInvalidBrokerRedirectURI
{
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];

    XCTestExpectation *expectation = [self expectationWithDescription:@"Expectation"];
    [context setCredentialsType:AD_CREDENTIALS_AUTO];
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:[NSURL URLWithString:@"urn:ietf:wg:oauth:2.0:oob"]
                      completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_TOKENBROKER_INVALID_REDIRECT_URI);
         XCTAssertNil(result.authority);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testBadExtraQueryParameters
{
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];

    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenWithResource with bad extra query parameters."];
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                               userId:TEST_USER_ID
                 extraQueryParameters:@"login_hint=test1@馬克英家.com"
                      completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);
         ADTAssertContains(result.error.errorDetails, @"extraQueryParameters");
         XCTAssertNil(result.authority);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testAssertionBadAssertion
{
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];

    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenForAssertion with bad assertion."];
    NSString *assertion = nil;
    [context acquireTokenForAssertion:assertion
                        assertionType:AD_SAML1_1
                             resource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                               userId:TEST_USER_ID
                      completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);
         ADTAssertContains(result.error.errorDetails, @"assertion");

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testAssertionCached
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];

    // Add a token item to return in the cache
    ADALTokenCacheItem* item = [self adCreateCacheItem];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);

    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenForAssertion with cached assertion."];
    [context acquireTokenForAssertion:@"some assertion"
                        assertionType:AD_SAML1_1
                             resource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                               userId:TEST_USER_ID
                      completionBlock:^(ADALAuthenticationResult *result)
    {
        XCTAssertNotNil(result);
        XCTAssertEqual(result.status, AD_SUCCEEDED);
        XCTAssertNotNil(result.tokenCacheItem);
        XCTAssertEqualObjects(result.tokenCacheItem, item);

        [expectation fulfill];
    }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testAssertionNetwork
{
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    NSUUID* correlationId = TEST_CORRELATION_ID;

    NSString* broadRefreshToken = @"broad refresh token testAcquireTokenWithNoPrompt";
    NSString* anotherAccessToken = @"another access token testAcquireTokenWithNoPrompt";
    NSString* assertion = @"some assertion";
    NSString* base64Assertion = [[assertion dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0];

    NSMutableDictionary *headers = [[ADTestURLResponse defaultHeaders] mutableCopy];
    headers[MSID_OAUTH2_CORRELATION_ID_REQUEST_VALUE] = [correlationId UUIDString];

    ADTestURLResponse* response = [ADTestURLResponse requestURLString:@"https://login.windows.net/contoso.com/oauth2/token"
                                                       requestHeaders:headers
                                                    requestParamsBody:@{ MSID_OAUTH2_GRANT_TYPE : MSID_OAUTH2_SAML11_BEARER_VALUE,
                                                                         MSID_OAUTH2_SCOPE : MSID_OAUTH2_SCOPE_OPENID_VALUE,
                                                                         MSID_OAUTH2_RESOURCE : TEST_RESOURCE,
                                                                         MSID_OAUTH2_CLIENT_ID : TEST_CLIENT_ID,
                                                                         MSID_OAUTH2_ASSERTION : base64Assertion }
                                                    responseURLString:@"https://contoso.com"
                                                         responseCode:400
                                                     httpHeaderFields:@{ MSID_OAUTH2_CORRELATION_ID_REQUEST_VALUE : [correlationId UUIDString] }
                                                     dictionaryAsJSON:@{ MSID_OAUTH2_ACCESS_TOKEN : anotherAccessToken,
                                                                         MSID_OAUTH2_REFRESH_TOKEN : broadRefreshToken,                                                                         MSID_OAUTH2_TOKEN_TYPE : TEST_ACCESS_TOKEN_TYPE,
                                                                         MSID_OAUTH2_RESOURCE : TEST_RESOURCE,
                                                                         MSID_OAUTH2_GRANT_TYPE : MSID_OAUTH2_SAML11_BEARER_VALUE,
                                                                         MSID_OAUTH2_SCOPE : MSID_OAUTH2_SCOPE_OPENID_VALUE                                                                         }];
    [ADTestURLSession addResponse:response];

    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenForAssertion"];
    [context acquireTokenForAssertion:assertion
                        assertionType:AD_SAML1_1
                             resource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                               userId:TEST_USER_ID
                      completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         XCTAssertNil(result.error);
         XCTAssertNotNil(result.tokenCacheItem);
         XCTAssertEqualObjects(result.tokenCacheItem.refreshToken, broadRefreshToken);
         XCTAssertEqualObjects(result.accessToken, anotherAccessToken);
         XCTAssertEqualObjects(result.correlationId, correlationId);
         XCTAssertEqualObjects(result.authority, TEST_AUTHORITY);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];

    XCTAssertTrue([ADTestURLSession noResponsesLeft]);

    ADALAuthenticationError *error = nil;

    NSArray* allItems = [self.cacheDataSource allItems:&error];
    XCTAssertNil(error);
    XCTAssertNotNil(allItems);
    XCTAssertEqual(allItems.count, 2);

    ADALTokenCacheItem* mrrtItem = nil;
    ADALTokenCacheItem* atItem = nil;

    // Pull the MRRT and AT items out of the cache
    for (ADALTokenCacheItem * item in allItems)
    {
        if (item.refreshToken)
        {
            mrrtItem = item;
        }
        else if (item.accessToken)
        {
            atItem = item;
        }
    }

    XCTAssertNotNil(atItem);
    XCTAssertNotNil(atItem.accessToken);

    XCTAssertNotNil(mrrtItem);
    XCTAssertNotNil(mrrtItem.refreshToken);
}


- (void)testCachedWithNilUserId
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];

    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenWithResource"];

    // Add a token item to return in the cache
    ADALTokenCacheItem* item = [self adCreateCacheItem:@"eric@contoso.com"];
    BOOL result =  [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);
    XCTAssertTrue(result);

    // Because there's only one user in the cache calling acquire token with nil userId should
    // return this one item.
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                      completionBlock:^(ADALAuthenticationResult *result)
    {
        XCTAssertNotNil(result);
        XCTAssertEqual(result.status, AD_SUCCEEDED);
        XCTAssertNil(result.error);
        XCTAssertNotNil(result.tokenCacheItem);
        XCTAssertEqualObjects(result.tokenCacheItem, item);
        XCTAssertEqualObjects(result.authority, TEST_AUTHORITY);

        [expectation fulfill];
    }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testCachedWithNilUserId_whenExpiredAccessToken_shouldRefreshUsingRT
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];

    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenWithResource"];

    // Add a token item to return in the cache
    ADALTokenCacheItem* item = [self adCreateCacheItem:nil];
    item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:-3600];
    BOOL result =  [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);
    XCTAssertTrue(result);

    // ADFSv3 only returns access token and no id_token nor refresh_token in its response
    ADTestURLResponse *response = [self adResponseRefreshToken:TEST_REFRESH_TOKEN
                                                     authority:TEST_AUTHORITY
                                               requestResource:TEST_RESOURCE
                                              responseResource:nil
                                                      clientId:TEST_CLIENT_ID
                                                 correlationId:TEST_CORRELATION_ID
                                               newRefreshToken:nil
                                                newAccessToken:@"new access token"
                                                    newIDToken:nil];

    [ADTestURLSession addResponse:response];

    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         XCTAssertNotNil(result.tokenCacheItem);
         XCTAssertTrue([result.correlationId isKindOfClass:[NSUUID class]]);
         XCTAssertEqualObjects(result.accessToken, @"new access token");
         XCTAssertEqualObjects(result.authority, TEST_AUTHORITY);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];

    // Verify cache updated properly and refresh token is persisted
    NSArray* allItems = [self.cacheDataSource allItems:&error];
    XCTAssertNil(error);
    XCTAssertEqual(allItems.count, 1);

    ADALTokenCacheItem *adfsToken = allItems[0];
    XCTAssertEqualObjects(adfsToken.refreshToken, TEST_REFRESH_TOKEN);
    XCTAssertEqualObjects(adfsToken.accessToken, @"new access token");
    XCTAssertNil(adfsToken.userInformation);
}

- (void)testFailsWithNilUserIdAndMultipleCachedUsers
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];

    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenWithResource"];

    // Add a token item to return in the cache
    [self.cacheDataSource addOrUpdateItem:[self adCreateCacheItem:@"eric@contoso.com"] correlationId:nil error:&error];
    [self.cacheDataSource addOrUpdateItem:[self adCreateCacheItem:@"stan@contoso.com"] correlationId:nil error:&error];

    // Because there's only one user in the cache calling acquire token with nil userId should
    // return this one item.
    NSString *userId = nil;
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                               userId:userId
                      completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertNil(result.tokenCacheItem);
         XCTAssertEqual(result.error.code, AD_ERROR_CACHE_MULTIPLE_USERS);
         XCTAssertNil(result.authority);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testCachedWithNoIdtoken
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"Expectation"];

    // Add a token item to return in the cache
    ADALTokenCacheItem* item = [self adCreateCacheItem:nil];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];

    // Because there's only one user in the cache calling acquire token should return that
    // item, even though there is no userId info in the item and we specified a user id.
    // This is done for ADFS users where a login hint might have been specified but we
    // can't verify it.
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                               userId:@"eric@contoso.com"
                      completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         XCTAssertNil(result.error);
         XCTAssertNotNil(result.tokenCacheItem);
         XCTAssertEqualObjects(result.tokenCacheItem, item);
         XCTAssertEqualObjects(result.authority, TEST_AUTHORITY);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testSilentNothingCached
{
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    // With nothing cached the operation should fail telling the developer that
    // user input is required.
    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_SERVER_USER_INPUT_NEEDED);
         XCTAssertNil(result.authority);

         [expectation fulfill];
    }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testSilentItemCached
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    // Add a token item to return in the cache
    ADALTokenCacheItem* item = [self adCreateCacheItem];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];

    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         XCTAssertNotNil(result.tokenCacheItem);
         XCTAssertEqualObjects(result.tokenCacheItem, item);
         XCTAssertEqualObjects(result.authority, TEST_AUTHORITY);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}

#if TARGET_OS_IPHONE

- (void)testAcquireTokenSilent_whenAccessTokenCached_andEnrollmentIdRequired_andCorrectEnrollmentIdPassed_shouldReturnToken
{
    [ADALEnrollmentGateway setEnrollmentIdsWithJsonBlob:[ADALEnrollmentGateway getTestEnrollmentIDJSON]];
    [ADALEnrollmentGateway setIntuneMAMResourceWithJsonBlob:[ADALEnrollmentGateway getTestResourceJSON]];
    
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];
    
    // Add a token item to return in the cache
    ADALTokenCacheItem* item = [self adCreateCacheItem];
    item.enrollmentId = @"adf79e3f-mike-454d-9f0f-2299e76dbfd5";
    item.applicationIdentifier = @"com.microsoft.unittesthost";
    
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];
    
    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         XCTAssertNotNil(result.tokenCacheItem);
         XCTAssertEqualObjects(result.tokenCacheItem, item);
         XCTAssertEqualObjects(result.authority, TEST_AUTHORITY);
         
         [expectation fulfill];
     }];
    
    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testAcquireTokenSilent_whenAccessTokenCached_andEnrollmentIdRequired_andNoEnrollmentIdPassed_shouldReturnNil
{
    [ADALEnrollmentGateway setEnrollmentIdsWithJsonBlob:[ADALEnrollmentGateway getTestEnrollmentIDJSON]];
    [ADALEnrollmentGateway setIntuneMAMResourceWithJsonBlob:[ADALEnrollmentGateway getTestResourceJSON]];
    
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];
    
    // Add a token item to return in the cache
    ADALTokenCacheItem* item = [self adCreateCacheItem];
    item.enrollmentId = @"wrong-enrollmentId";
    item.applicationIdentifier = @"com.microsoft.unittesthost";
    item.refreshToken = nil;
    
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];
    
    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_SERVER_USER_INPUT_NEEDED);
         XCTAssertNil(result.authority);
         
         [expectation fulfill];
     }];
    
    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testAcquireTokenSilent_whenExpiredAccessTokenCached_andEnrollmentIdRequired_andCorrectEnrollmentIdPassed_shouldReturnNil
{
    [ADALEnrollmentGateway setEnrollmentIdsWithJsonBlob:[ADALEnrollmentGateway getTestEnrollmentIDJSON]];
    [ADALEnrollmentGateway setIntuneMAMResourceWithJsonBlob:[ADALEnrollmentGateway getTestResourceJSON]];
    
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];
    
    // Add a token item to return in the cache
    ADALTokenCacheItem* item = [self adCreateCacheItem];
    item.enrollmentId = @"adf79e3f-mike-454d-9f0f-2299e76dbfd5";
    item.expiresOn = [NSDate date];
    item.applicationIdentifier = @"com.microsoft.unittesthost";
    item.refreshToken = nil;
    
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];
    
    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_SERVER_USER_INPUT_NEEDED);
         XCTAssertNil(result.authority);
         
         [expectation fulfill];
     }];
    
    [self waitForExpectations:@[expectation] timeout:1];
    
    // Also verify the expired item has been removed from the cache
    NSArray* allItems = [self.cacheDataSource allItems:&error];
    XCTAssertNil(error);
    XCTAssertEqual(allItems.count, 0);
}

- (void)testAcquireTokenSilent_whenExpiredAccessTokenCached_andNoEnrollmentIdProvided_shouldRemoveExpiredToken

{
    [ADALEnrollmentGateway setEnrollmentIdsWithJsonBlob:[ADALEnrollmentGateway getTestEnrollmentIDJSON]];
    [ADALEnrollmentGateway setIntuneMAMResourceWithJsonBlob:[ADALEnrollmentGateway getTestResourceJSON]];
    
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];
    
    // Add a token item to return in the cache
    ADALTokenCacheItem* item = [self adCreateCacheItem];
    item.enrollmentId = @"wrongenroll";
    item.expiresOn = [NSDate date];
    item.applicationIdentifier = @"com.microsoft.unittesthost";
    item.refreshToken = nil;
    
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];
    
    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_SERVER_USER_INPUT_NEEDED);
         XCTAssertNil(result.authority);
         
         [expectation fulfill];
     }];
    
    [self waitForExpectations:@[expectation] timeout:1];
    
    // Also verify the expired item has been removed from the cache
    NSArray* allItems = [self.cacheDataSource allItems:&error];
    XCTAssertNil(error);
    XCTAssertEqual(allItems.count, 0);
}
#endif

- (void)testSilentExpiredItemCached
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    // Add a expired access token with no refresh token to the cache
    ADALTokenCacheItem* item = [self adCreateCacheItem];
    item.expiresOn = [NSDate date];
    item.refreshToken = nil;
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);

    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_SERVER_USER_INPUT_NEEDED);
         XCTAssertNil(result.authority);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];

    // Also verify the expired item has been removed from the cache
    NSArray* allItems = [self.cacheDataSource allItems:&error];
    XCTAssertNil(error);
    XCTAssertEqual(allItems.count, 0);
}

- (void)testSilentBadRefreshToken
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    // Add a expired access token with refresh token to the cache
    ADALTokenCacheItem* item = [self adCreateCacheItem];
    item.expiresOn = [NSDate date];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);

    // Set the response to reject the refresh token
    [ADTestURLSession addResponse:[self adDefaultBadRefreshTokenResponse]];

    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         // Request should fail because it's silent and getting a new RT requires showing UI
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_SERVER_USER_INPUT_NEEDED);
         XCTAssertNil(result.authority);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];

    XCTAssertTrue([ADTestURLSession noResponsesLeft]);

    // Also verify the expired item has been removed from the cache
    NSArray* allItems = [self.cacheDataSource allItems:&error];
    XCTAssertNil(error);
    XCTAssertEqual(allItems.count, 0);
}

- (void)testSilentExpiredATBadMRRT
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    // Add a expired access token with refresh token to the cache
    ADALTokenCacheItem* item = [self adCreateATCacheItem];
    item.expiresOn = [NSDate date];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);

    // Add an MRRT to the cache as well
    [self.cacheDataSource addOrUpdateItem:[self adCreateMRRTCacheItem] correlationId:nil error:&error];
    XCTAssertNil(error);

    // Set the response to reject the refresh token
    [ADTestURLSession addResponse:[self adDefaultBadRefreshTokenResponse]];

    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         // Request should fail because it's silent and getting a new RT requires showing UI
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_SERVER_USER_INPUT_NEEDED);
         XCTAssertNil(result.authority);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];

    // Verify that both the expired AT and the rejected MRRT are removed from the cache
    NSArray* allItems = [self.cacheDataSource allItems:&error];
    XCTAssertNil(error);

    XCTAssertTrue([ADTestURLSession noResponsesLeft]);
    XCTAssertEqual(allItems.count, 0);

    expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    // The next acquire token call should fail immediately without hitting network
    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         // Request should fail because it's silent and getting a new RT requires showing UI
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_SERVER_USER_INPUT_NEEDED);
         XCTAssertNil(result.authority);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testSilentExpiredATRefreshMRRTNetwork
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    // Add a expired access token with refresh token to the cache
    ADALTokenCacheItem* item = [self adCreateATCacheItem];
    item.expiresOn = [NSDate date];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);

    // Add an MRRT to the cache as well
    [self.cacheDataSource addOrUpdateItem:[self adCreateMRRTCacheItem] correlationId:nil error:&error];
    XCTAssertNil(error);

    [ADTestURLSession addResponse:[self adDefaultRefreshResponse:@"new refresh token" accessToken:@"new access token" newIDToken:[self adDefaultIDToken]]];

    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         XCTAssertNotNil(result.tokenCacheItem);
         XCTAssertTrue([result.correlationId isKindOfClass:[NSUUID class]]);
         XCTAssertEqualObjects(result.accessToken, @"new access token");
         XCTAssertEqualObjects(result.authority, TEST_AUTHORITY);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];

    NSArray* allItems = [self.cacheDataSource allItems:&error];
    XCTAssertNil(error);
    XCTAssertNotNil(allItems);
    XCTAssertEqual(allItems.count, 2);

    ADALTokenCacheItem* mrrtItem = nil;
    ADALTokenCacheItem* atItem = nil;

    // Pull the MRRT and AT items out of the cache
    for (ADALTokenCacheItem * item in allItems)
    {
        if (item.refreshToken)
        {
            mrrtItem = item;
        }
        else if (item.accessToken)
        {
            atItem = item;
        }
    }

    XCTAssertNotNil(mrrtItem);
    XCTAssertNotNil(atItem);

    XCTAssertNil(atItem.refreshToken);
    XCTAssertNil(mrrtItem.accessToken);

    // Make sure the tokens got updated
    XCTAssertEqualObjects(atItem.accessToken, @"new access token");
    XCTAssertEqualObjects(mrrtItem.refreshToken, @"new refresh token");
}

- (void)testAcquireTokenSilent_whenRedeemingMRRT_withNSNumbersInParsedJSON
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    // Add a expired access token with refresh token to the cache
    ADALTokenCacheItem* item = [self adCreateATCacheItem];
    item.expiresOn = [NSDate date];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);

    // Add an MRRT to the cache as well
    [self.cacheDataSource addOrUpdateItem:[self adCreateMRRTCacheItem] correlationId:nil error:&error];
    XCTAssertNil(error);

    ADTestURLResponse *response = [self adDefaultRefreshResponse:@"new refresh token" accessToken:@"new access token" newIDToken:[self adDefaultIDToken]];
    // We're using a hardcoded JSON string in the test because we want to test a specific string to see how it is decoded
    // and make sure it gets handled properly
    NSString *responseJson = [NSString stringWithFormat:@"{\"refresh_token\":\"new refresh token\",\"access_token\":\"new access token\",\"id_token\":\"%@\",\"resource\":\"" TEST_RESOURCE "\",\"expires_in\":3600,\"ext_expires_in\":360000}", [self adDefaultIDToken]];
    [response setResponseData:[responseJson dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:YES]];

    [ADTestURLSession addResponse:response];

    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         XCTAssertNotNil(result.tokenCacheItem);
         XCTAssertTrue([result.correlationId isKindOfClass:[NSUUID class]]);
         XCTAssertEqualObjects(result.accessToken, @"new access token");
         XCTAssertEqualObjects(result.authority, TEST_AUTHORITY);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];

    NSArray* allItems = [self.cacheDataSource allItems:&error];
    XCTAssertNil(error);
    XCTAssertNotNil(allItems);
    XCTAssertEqual(allItems.count, 2);

    ADALTokenCacheItem* mrrtItem = nil;
    ADALTokenCacheItem* atItem = nil;

    // Pull the MRRT and AT items out of the cache
    for (ADALTokenCacheItem * item in allItems)
    {
        if (item.refreshToken)
        {
            mrrtItem = item;
        }
        else if (item.accessToken)
        {
            atItem = item;
        }
    }

    XCTAssertNotNil(mrrtItem);
    XCTAssertNotNil(atItem);

    XCTAssertNil(atItem.refreshToken);
    XCTAssertNil(mrrtItem.accessToken);

    // Make sure the tokens got updated
    XCTAssertEqualObjects(atItem.accessToken, @"new access token");
    XCTAssertEqualObjects(mrrtItem.refreshToken, @"new refresh token");
}

- (void)testMRRTNoNetworkConnection
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenWithResource"];

    // Add a expired access token with refresh token to the cache
    ADALTokenCacheItem* item = [self adCreateATCacheItem];
    item.expiresOn = [NSDate date];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);

    // Add an MRRT to the cache as well
    ADALTokenCacheItem* mrrtItem = [self adCreateMRRTCacheItem];
    [self.cacheDataSource addOrUpdateItem:mrrtItem correlationId:nil error:&error];
    XCTAssertNil(error);

    // Set up the mock connection to simulate a no internet connection error
    ADTestURLResponse* response =
    [ADTestURLResponse request:[NSURL URLWithString:TEST_AUTHORITY "/oauth2/token"]
              respondWithError:[NSError errorWithDomain:NSURLErrorDomain
                                                   code:NSURLErrorNotConnectedToInternet
                                               userInfo:nil]];
    [response setRequestHeaders:[ADTestURLResponse defaultHeaders]];
    [response setUrlFormEncodedBody:@{ @"resource" : TEST_RESOURCE,
                                       @"client_id" : TEST_CLIENT_ID,
                                       @"grant_type" : @"refresh_token",
                                       MSID_OAUTH2_CLIENT_INFO: @"1",
                                       MSID_OAUTH2_SCOPE: @"openid",
                                       @"refresh_token" : TEST_REFRESH_TOKEN }];
    [ADTestURLSession addResponse:response];

    // Web UI should not attempt to launch when we fail to refresh the RT because there is no internet
    // connection
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                               userId:TEST_USER_ID
                      completionBlock:^(ADALAuthenticationResult *result)
    {
        XCTAssertNotNil(result);
        XCTAssertEqual(result.status, AD_FAILED);
        XCTAssertNotNil(result.error);
        XCTAssertNil(result.authority);

        [expectation fulfill];
    }];

    [self waitForExpectations:@[expectation] timeout:1];

    // The expired AT should be removed from the cache but the MRRT should still be there.
    NSArray* allItems = [self.cacheDataSource allItems:&error];
    XCTAssertNotNil(allItems);
    XCTAssertEqual(allItems.count, 1);
    XCTAssertEqualObjects(allItems[0], mrrtItem);
}

- (void)testAcquireTokenSilent_whenInteractionRequiredError_andSubError_shouldReturnSuberror
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];
    
    // Add an MRRT to the cache as well
    ADALTokenCacheItem* mrrtItem = [self adCreateMRRTCacheItem];
    [self.cacheDataSource addOrUpdateItem:mrrtItem correlationId:nil error:&error];
    XCTAssertNil(error);
    
    ADTestURLResponse* badFRTResponse =
    [self adResponseBadRefreshToken:@"refresh token"
                          authority:TEST_AUTHORITY
                           resource:TEST_RESOURCE
                           clientId:TEST_CLIENT_ID
                         oauthError:@"interaction_required"
                      oauthSubError:@"basic_action"
                      correlationId:TEST_CORRELATION_ID
                      requestParams:nil];
    
    // Set up the mock connection to reject the MRRT with an error that should cause it to not remove the MRRT
    [ADTestURLSession addResponse:badFRTResponse];
    
    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_SERVER_USER_INPUT_NEEDED);
         XCTAssertEqualObjects(result.error.userInfo[ADSuberrorKey], @"basic_action");
         XCTAssertNil(result.authority);
         
         [expectation fulfill];
     }];
    
    [self waitForExpectations:@[expectation] timeout:1];
    
    // The MRRT should still be in the cache
    NSArray* allItems = [self.cacheDataSource allItems:&error];
    XCTAssertNotNil(allItems);
    XCTAssertEqual(allItems.count, 1);
    XCTAssertEqualObjects(allItems[0], mrrtItem);
}

- (void)testAcquireTokenSilent_whenSubErrorNull_shouldReturnMainError
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    // Add an MRRT to the cache as well
    ADALTokenCacheItem* mrrtItem = [self adCreateMRRTCacheItem];
    [self.cacheDataSource addOrUpdateItem:mrrtItem correlationId:nil error:&error];
    XCTAssertNil(error);

    ADTestURLResponse* badFRTResponse =
    [self adResponseBadRefreshToken:@"refresh token"
                          authority:TEST_AUTHORITY
                           resource:TEST_RESOURCE
                           clientId:TEST_CLIENT_ID
                         oauthError:@"interaction_required"
                      oauthSubError:[NSNull null]
                      correlationId:TEST_CORRELATION_ID
                      requestParams:nil];

    // Set up the mock connection to reject the MRRT with an error that should cause it to not remove the MRRT
    [ADTestURLSession addResponse:badFRTResponse];

    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_SERVER_USER_INPUT_NEEDED);
         XCTAssertNil(result.error.userInfo[ADSuberrorKey]);
         XCTAssertNil(result.authority);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];

    // The MRRT should still be in the cache
    NSArray* allItems = [self.cacheDataSource allItems:&error];
    XCTAssertNotNil(allItems);
    XCTAssertEqual(allItems.count, 1);
    XCTAssertEqualObjects(allItems[0], mrrtItem);
}

- (void)testAcquireTokenSilent_whenUnauthorizedClientAndProtectionPoliciesRequired_shouldReturnIntuneError
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];
    
    // Add an MRRT to the cache as well
    ADALTokenCacheItem* mrrtItem = [self adCreateMRRTCacheItem];
    [self.cacheDataSource addOrUpdateItem:mrrtItem correlationId:nil error:&error];
    XCTAssertNil(error);
    
    ADTestURLResponse* badFRTResponse =
    [self adResponseBadRefreshToken:@"refresh token"
                          authority:TEST_AUTHORITY
                           resource:TEST_RESOURCE
                           clientId:TEST_CLIENT_ID
                         oauthError:@"unauthorized_client"
                      oauthSubError:@"protection_policy_required"
                      correlationId:TEST_CORRELATION_ID
                      requestParams:nil];
    
    // Set up the mock connection to reject the MRRT with an error that should cause it to not remove the MRRT
    [ADTestURLSession addResponse:badFRTResponse];
    
    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_SERVER_PROTECTION_POLICY_REQUIRED);
         XCTAssertEqualObjects(result.error.protocolCode, @"unauthorized_client");
         XCTAssertEqualObjects(result.error.userInfo[ADSuberrorKey], @"protection_policy_required");
         XCTAssertNil(result.authority);
         
         [expectation fulfill];
     }];
    
    [self waitForExpectations:@[expectation] timeout:1];
    
    // The MRRT should still be in the cache
    NSArray* allItems = [self.cacheDataSource allItems:&error];
    XCTAssertNotNil(allItems);
    XCTAssertEqual(allItems.count, 1);
    XCTAssertEqualObjects(allItems[0], mrrtItem);
}

- (void)testMRRTUnauthorizedClient
{
    // Refresh tokens should only be deleted when the server returns a 'invalid_grant' error
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    // Add an MRRT to the cache as well
    ADALTokenCacheItem* mrrtItem = [self adCreateMRRTCacheItem];
    [self.cacheDataSource addOrUpdateItem:mrrtItem correlationId:nil error:&error];
    XCTAssertNil(error);

    // Set up the mock connection to reject the MRRT with an error that should cause it to not remove the MRRT
    [ADTestURLSession addResponse:[self adDefaultBadRefreshTokenResponseError:@"unauthorized_client"]];

    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                            completionBlock:^(ADALAuthenticationResult *result)
    {
        XCTAssertNotNil(result);
        XCTAssertEqual(result.status, AD_FAILED);
        XCTAssertNotNil(result.error);
        XCTAssertNil(result.authority);

        [expectation fulfill];
    }];

    [self waitForExpectations:@[expectation] timeout:1];

    // The MRRT should still be in the cache
    NSArray* allItems = [self.cacheDataSource allItems:&error];
    XCTAssertNotNil(allItems);
    XCTAssertEqual(allItems.count, 1);
    XCTAssertEqualObjects(allItems[0], mrrtItem);
}

- (void)testRequestRetryOnUnusualHttpResponse
{
    //Create a normal authority (not a test one):
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenWithResource"];

    // Add a expired access token with refresh token to the cache
    ADALTokenCacheItem* item = [self adCreateATCacheItem];
    item.expiresOn = [NSDate date];
    item.refreshToken = @"refresh token";
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);

    // Add an MRRT to the cache as well
    [self.cacheDataSource addOrUpdateItem:[self adCreateMRRTCacheItem] correlationId:nil error:&error];
    XCTAssertNil(error);
    
    ADTestURLResponse* response = [ADTestURLResponse requestURLString:@"https://login.windows.net/contoso.com/oauth2/token"
                                                    responseURLString:@"https://contoso.com"
                                                         responseCode:500
                                                     httpHeaderFields:@{ } // maybe shoehorn correlation ID here
                                                     dictionaryAsJSON:@{ MSID_OAUTH2_ERROR : @"server_error",
                                                                         MSID_OAUTH2_ERROR_DESCRIPTION : @"AADSTS90036: Non-retryable error has occurred." }];
    [response setRequestHeaders:[ADTestURLResponse defaultHeaders]];
    [response setUrlFormEncodedBody:@{ @"resource" : TEST_RESOURCE,
                                       @"client_id" : TEST_CLIENT_ID,
                                       @"grant_type" : @"refresh_token",
                                       MSID_OAUTH2_CLIENT_INFO: @"1",
                                       MSID_OAUTH2_SCOPE: MSID_OAUTH2_SCOPE_OPENID_VALUE,
                                       @"refresh_token" : TEST_REFRESH_TOKEN }];

    //It should hit network twice for trying and retrying the refresh token because it is an server error
    //Then hit network twice again for broad refresh token for the same reason
    //So totally 4 responses are added
    //If there is an infinite retry, exception will be thrown becasuse there is not enough responses
    [ADTestURLSession addResponse:response];
    [ADTestURLSession addResponse:response];

    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                               userId:TEST_USER_ID
                      completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];

    NSArray* allItems = [self.cacheDataSource allItems:&error];
    XCTAssertNotNil(allItems);
    XCTAssertEqual(allItems.count, 2);
}

- (void)testAdditionalServerProperties
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    id<ADALTokenCacheDataSource> cache = self.cacheDataSource;
    XCTAssertNotNil(cache);

    XCTAssertTrue([cache addOrUpdateItem:[self adCreateMRRTCacheItem] correlationId:nil error:&error]);
    XCTAssertNil(error);

    NSDictionary* additional = @{ @"arbitraryProperty" : @"save_me",
                                  @"thing-that-if-it-doesnt-get-saved-might-hose-us-later" : @"not-hosed" };

    ADTestURLResponse* response = [self adResponseRefreshToken:TEST_REFRESH_TOKEN
                                                     authority:TEST_AUTHORITY
                                                      resource:TEST_RESOURCE
                                                      clientId:TEST_CLIENT_ID
                                                 correlationId:TEST_CORRELATION_ID
                                               newRefreshToken:TEST_REFRESH_TOKEN
                                                newAccessToken:TEST_ACCESS_TOKEN
                                                    newIDToken:[self adDefaultIDToken]
                                              additionalFields:additional];

    [ADTestURLSession addResponse:response];

    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         XCTAssertNotNil(result.tokenCacheItem);
         XCTAssertEqualObjects(result.accessToken, TEST_ACCESS_TOKEN);

         NSDictionary* additionalServer = result.tokenCacheItem.additionalServer;
         XCTAssertNotNil(additionalServer);
         // We need to make sure the additionalServer dictionary contains everything in the additional
         // dictionary, but if there's other stuff there as well it's okay.
         for (NSString* key in additional)
         {
             XCTAssertEqualObjects(additionalServer[key], additional[key], @"Expected \"%@\" for \"%@\", Actual: \"%@\"", additionalServer[key], key, additional[key]);
         }
         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}

// Make sure that if we get a token response from the server that includes a family ID we cache it properly
- (void)testAcquireRefreshFamilyTokenNetwork
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    id<ADALTokenCacheDataSource> cache = self.cacheDataSource;
    XCTAssertNotNil(cache);

    XCTAssertTrue([cache addOrUpdateItem:[self adCreateMRRTCacheItem] correlationId:nil error:&error]);
    XCTAssertNil(error);

    ADTestURLResponse* response = [self adResponseRefreshToken:TEST_REFRESH_TOKEN
                                                     authority:TEST_AUTHORITY
                                                      resource:TEST_RESOURCE
                                                      clientId:TEST_CLIENT_ID
                                                 correlationId:TEST_CORRELATION_ID
                                               newRefreshToken:TEST_REFRESH_TOKEN
                                                newAccessToken:TEST_ACCESS_TOKEN
                                                    newIDToken:[self adDefaultIDToken]
                                              additionalFields:@{ ADAL_CLIENT_FAMILY_ID : @"1"}];

    [ADTestURLSession addResponse:response];

    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADALAuthenticationResult *result)
    {
        XCTAssertNotNil(result);
        XCTAssertEqual(result.status, AD_SUCCEEDED);
        XCTAssertNotNil(result.tokenCacheItem);
        XCTAssertEqualObjects(result.accessToken, TEST_ACCESS_TOKEN);
        XCTAssertEqualObjects(result.tokenCacheItem.familyId, @"1");
        XCTAssertEqualObjects(result.authority, TEST_AUTHORITY);
        [expectation fulfill];
    }];

    [self waitForExpectations:@[expectation] timeout:1];

    // Verfiy the FRT is now properly stored in cache
    ADALTokenCacheKey* frtKey = [ADALTokenCacheKey keyWithAuthority:TEST_AUTHORITY
                                                       resource:nil
                                                       clientId:@"foci-1"
                                                          error:&error];
    XCTAssertNotNil(frtKey);
    XCTAssertNil(error);

    ADALTokenCacheItem* frtItem = [cache getItemWithKey:frtKey
                                               userId:TEST_USER_ID
                                        correlationId:nil
                                                error:&error];
    XCTAssertNotNil(frtItem);
    XCTAssertNil(error);

    XCTAssertEqualObjects(TEST_REFRESH_TOKEN, frtItem.refreshToken);
}

- (void)testAcquireTokenUsingFRT
{
    // Simplest FRT case, the only RT available is the FRT so that would should be the one used
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    id<ADALTokenCacheDataSource> cache = self.cacheDataSource;
    XCTAssertNotNil(cache);

    XCTAssertTrue([cache addOrUpdateItem:[self adCreateFRTCacheItem] correlationId:nil error:&error]);
    XCTAssertNil(error);

    ADTestURLResponse* response = [self adResponseRefreshToken:@"family refresh token"
                                                     authority:TEST_AUTHORITY
                                               requestResource:TEST_RESOURCE
                                              responseResource:TEST_RESOURCE
                                                      clientId:TEST_CLIENT_ID
                                                requestHeaders:nil
                                                 correlationId:TEST_CORRELATION_ID
                                               newRefreshToken:@"new family refresh token"
                                                newAccessToken:TEST_ACCESS_TOKEN
                                                    newIDToken:[self adDefaultIDToken]
                                              additionalFields:@{ ADAL_CLIENT_FAMILY_ID : @"1"}
                                               responseHeaders:@{@"x-ms-clitelem" : @"1,0,0,2550.0643,I"}];

    [ADTestURLSession addResponse:response];

    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         XCTAssertNotNil(result.tokenCacheItem);
         XCTAssertEqualObjects(result.accessToken, TEST_ACCESS_TOKEN);
         XCTAssertEqualObjects(result.tokenCacheItem.refreshToken, @"new family refresh token");
         XCTAssertEqualObjects(result.tokenCacheItem.familyId, @"1");
         XCTAssertEqualObjects(result.authority, TEST_AUTHORITY);
         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testAcquireTokenMRRTFailFRTFallback
{
    // In this case we have an invalid MRRT that's not tagged as being a family
    // token, but a valid FRT, we want to make sure that the FRT gets tried once
    // the MRRT fails.

    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    id<ADALTokenCacheDataSource> cache = self.cacheDataSource;
    XCTAssertNotNil(cache);

    XCTAssertTrue([cache addOrUpdateItem:[self adCreateFRTCacheItem] correlationId:nil error:&error]);
    XCTAssertTrue([cache addOrUpdateItem:[self adCreateMRRTCacheItem] correlationId:nil error:&error]);
    XCTAssertNil(error);

    // This is the error message the server sends when MFA is required, it should cause the token to
    // not be deleted right away, but when we get the success response with the FRT it should cause
    // the MRRT to be replaced
    ADTestURLResponse* badMRRT = [self adDefaultBadRefreshTokenResponseError:@"interaction_required"];

    ADTestURLResponse* frtResponse =
    [self adResponseRefreshToken:@"family refresh token"
                       authority:TEST_AUTHORITY
                        resource:TEST_RESOURCE
                        clientId:TEST_CLIENT_ID
                   correlationId:TEST_CORRELATION_ID
                 newRefreshToken:@"new family refresh token"
                  newAccessToken:TEST_ACCESS_TOKEN
                      newIDToken:[self adDefaultIDToken]
                additionalFields:@{ ADAL_CLIENT_FAMILY_ID : @"1"}];

    [ADTestURLSession addResponses:@[badMRRT, frtResponse]];

    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         XCTAssertNotNil(result.tokenCacheItem);
         XCTAssertEqualObjects(result.accessToken, TEST_ACCESS_TOKEN);
         XCTAssertEqualObjects(result.tokenCacheItem.refreshToken, @"new family refresh token");
         XCTAssertEqualObjects(result.tokenCacheItem.familyId, @"1");
         XCTAssertEqualObjects(result.authority, TEST_AUTHORITY);
         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];

    // Also make sure that cache state is properly updated
    ADALTokenCacheKey* mrrtKey = [ADALTokenCacheKey keyWithAuthority:TEST_AUTHORITY
                                                        resource:nil
                                                        clientId:TEST_CLIENT_ID
                                                           error:&error];
    XCTAssertNotNil(mrrtKey);
    XCTAssertNil(error);

    ADALTokenCacheItem* mrrtItem = [cache getItemWithKey:mrrtKey userId:TEST_USER_ID correlationId:nil error:&error];
    XCTAssertNotNil(mrrtItem);
    XCTAssertNil(error);
    XCTAssertEqualObjects(mrrtItem.refreshToken, @"new family refresh token");
    XCTAssertEqualObjects(mrrtItem.familyId, @"1");

    ADALTokenCacheKey* frtKey = [ADALTokenCacheKey keyWithAuthority:TEST_AUTHORITY
                                                       resource:nil
                                                       clientId:@"foci-1"
                                                          error:&error];
    XCTAssertNotNil(frtKey);
    XCTAssertNil(error);

    ADALTokenCacheItem* frtItem = [cache getItemWithKey:frtKey userId:TEST_USER_ID correlationId:nil error:&error];
    XCTAssertNotNil(frtItem);
    XCTAssertNil(error);
    XCTAssertEqualObjects(frtItem.refreshToken, @"new family refresh token");
}

- (void)testFRTFailFallbackToMRRT
{
    // In this case we have a MRRT marked with a family ID and a FRT that does not work, here we want
    // to make sure that we fallback onto the MRRT.
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    id<ADALTokenCacheDataSource> cache = self.cacheDataSource;
    XCTAssertNotNil(cache);

    XCTAssertTrue([cache addOrUpdateItem:[self adCreateFRTCacheItem] correlationId:nil error:&error]);
    XCTAssertTrue([cache addOrUpdateItem:[self adCreateMRRTCacheItem:TEST_USER_ID familyId:@"1"] correlationId:nil error:&error]);
    XCTAssertNil(error);

    ADTestURLResponse* badFRTResponse =
    [self adResponseBadRefreshToken:@"family refresh token"
                          authority:TEST_AUTHORITY
                           resource:TEST_RESOURCE
                           clientId:TEST_CLIENT_ID
                         oauthError:@"invalid_grant"
                      oauthSubError:nil
                      correlationId:TEST_CORRELATION_ID
                      requestParams:nil];
    
    ADTestURLResponse* mrrtResponse =
    [self adResponseRefreshToken:TEST_REFRESH_TOKEN
                       authority:TEST_AUTHORITY
                        resource:TEST_RESOURCE
                        clientId:TEST_CLIENT_ID
                   correlationId:TEST_CORRELATION_ID
                 newRefreshToken:@"new family refresh token"
                  newAccessToken:@"new access token"
                      newIDToken:[self adDefaultIDToken]
                additionalFields:@{ ADAL_CLIENT_FAMILY_ID : @"1"}];

    [ADTestURLSession addResponses:@[badFRTResponse, mrrtResponse]];

    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                            completionBlock:^(ADALAuthenticationResult *result)
    {
        XCTAssertNotNil(result);
        XCTAssertEqual(result.status, AD_SUCCEEDED);
        XCTAssertNotNil(result.tokenCacheItem);
        XCTAssertEqualObjects(result.accessToken, @"new access token");
        XCTAssertEqualObjects(result.tokenCacheItem.refreshToken, @"new family refresh token");
        XCTAssertEqualObjects(result.tokenCacheItem.familyId, @"1");
        XCTAssertEqualObjects(result.authority, TEST_AUTHORITY);
        [expectation fulfill];
    }];

    [self waitForExpectations:@[expectation] timeout:1];

    // Make sure that cache state is properly updated
    ADALTokenCacheKey* mrrtKey = [ADALTokenCacheKey keyWithAuthority:TEST_AUTHORITY
                                                        resource:nil
                                                        clientId:TEST_CLIENT_ID
                                                           error:&error];
    XCTAssertNotNil(mrrtKey);
    XCTAssertNil(error);

    ADALTokenCacheItem* mrrtItem = [cache getItemWithKey:mrrtKey userId:TEST_USER_ID correlationId:nil error:&error];
    XCTAssertNotNil(mrrtItem);
    XCTAssertNil(error);
    XCTAssertEqualObjects(mrrtItem.refreshToken, @"new family refresh token");
    XCTAssertEqualObjects(mrrtItem.familyId, @"1");

    ADALTokenCacheKey* frtKey = [ADALTokenCacheKey keyWithAuthority:TEST_AUTHORITY
                                                       resource:nil
                                                       clientId:@"foci-1"
                                                          error:&error];
    XCTAssertNotNil(frtKey);
    XCTAssertNil(error);

    ADALTokenCacheItem* frtItem = [cache getItemWithKey:frtKey userId:TEST_USER_ID correlationId:nil error:&error];
    XCTAssertNotNil(frtItem);
    XCTAssertNil(error);
    XCTAssertEqualObjects(frtItem.refreshToken, @"new family refresh token");
}

- (void)testFociMRRTWithNoFRT
{
    // This case is to make sure that if we have a MRRT marked with a family ID but no FRT in the
    // cache that we still use the MRRT
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    id<ADALTokenCacheDataSource> cache = self.cacheDataSource;
    XCTAssertNotNil(cache);

    XCTAssertTrue([cache addOrUpdateItem:[self adCreateMRRTCacheItem:TEST_USER_ID familyId:@"1"] correlationId:nil error:&error]);
    XCTAssertNil(error);

    ADTestURLResponse* mrrtResponse =
    [self adResponseRefreshToken:TEST_REFRESH_TOKEN
                       authority:TEST_AUTHORITY
                        resource:TEST_RESOURCE
                        clientId:TEST_CLIENT_ID
                   correlationId:TEST_CORRELATION_ID
                 newRefreshToken:@"new family refresh token"
                  newAccessToken:@"new access token"
                      newIDToken:[self adDefaultIDToken]
                additionalFields:@{ ADAL_CLIENT_FAMILY_ID : @"1"}];
    [ADTestURLSession addResponse:mrrtResponse];

    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         XCTAssertNotNil(result.tokenCacheItem);
         XCTAssertEqualObjects(result.accessToken, @"new access token");
         XCTAssertEqualObjects(result.tokenCacheItem.refreshToken, @"new family refresh token");
         XCTAssertEqualObjects(result.tokenCacheItem.familyId, @"1");
         XCTAssertEqualObjects(result.authority, TEST_AUTHORITY);
         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];

    // Make sure that cache state is properly updated
    ADALTokenCacheKey* mrrtKey = [ADALTokenCacheKey keyWithAuthority:TEST_AUTHORITY
                                                        resource:nil
                                                        clientId:TEST_CLIENT_ID
                                                           error:&error];
    XCTAssertNotNil(mrrtKey);
    XCTAssertNil(error);

    ADALTokenCacheItem* mrrtItem = [cache getItemWithKey:mrrtKey userId:TEST_USER_ID correlationId:nil error:&error];
    XCTAssertNotNil(mrrtItem);
    XCTAssertNil(error);
    XCTAssertEqualObjects(mrrtItem.refreshToken, @"new family refresh token");
    XCTAssertEqualObjects(mrrtItem.familyId, @"1");

    ADALTokenCacheKey* frtKey = [ADALTokenCacheKey keyWithAuthority:TEST_AUTHORITY
                                                       resource:nil
                                                       clientId:@"foci-1"
                                                          error:&error];
    XCTAssertNotNil(frtKey);
    XCTAssertNil(error);

    ADALTokenCacheItem* frtItem = [cache getItemWithKey:frtKey userId:TEST_USER_ID correlationId:nil error:&error];
    XCTAssertNotNil(frtItem);
    XCTAssertNil(error);
    XCTAssertEqualObjects(frtItem.refreshToken, @"new family refresh token");
}

- (void)testExtraQueryParams
{
    // TODO: Requires testing auth code flow
}

- (void)testUserSignIn
{
    // TODO: Requires testing auth code flow
}

- (void)testADFSUserSignIn
{
    // TODO: Requires testing auth code flow

    // Sign in a user without an idtoken coming back
}

- (void)testInstanceAwareSignIn
{
    // TODO: Requires testing auth code flow

    // Pass instance_aware=true as extra query parameter and make sure correct
    // token endpoint is used and token is cached with correct authority url
}

- (void)testResilencyTokenReturn
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    id<ADALTokenCacheDataSource> cache = self.cacheDataSource;
    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithResource"];

    // Add an MRRT to the cache
    [cache addOrUpdateItem:[self adCreateMRRTCacheItem] correlationId:nil error:&error];
    XCTAssertNil(error);

    // Response with ext_expires_in value
    [ADTestURLSession addResponse:[self adResponseRefreshToken:TEST_REFRESH_TOKEN
                                                        authority:TEST_AUTHORITY
                                                         resource:TEST_RESOURCE
                                                         clientId:TEST_CLIENT_ID
                                                    correlationId:TEST_CORRELATION_ID
                                                  newRefreshToken:@"refresh token"
                                                   newAccessToken:@"access token"
                                                    newIDToken:[self adDefaultIDToken]
                                                 additionalFields:@{ @"ext_expires_in" : @"3600"}]];

    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                               userId:TEST_USER_ID
                      completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         XCTAssertNil(result.error);
         XCTAssertEqualObjects(result.authority, TEST_AUTHORITY);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];

    // retrieve the AT from cache
    ADALTokenCacheKey* atKey = [ADALTokenCacheKey keyWithAuthority:TEST_AUTHORITY
                                                        resource:TEST_RESOURCE
                                                        clientId:TEST_CLIENT_ID
                                                           error:&error];
    XCTAssertNotNil(atKey);
    XCTAssertNil(error);

    ADALTokenCacheItem* atItem = [cache getItemWithKey:atKey userId:TEST_USER_ID correlationId:nil error:&error];
    XCTAssertNotNil(atItem);
    XCTAssertNil(error);

    // Make sure ext_expires_on is in the AT and set with proper value
    NSDate* extExpires = [atItem.additionalServer valueForKey:@"extended_expires_on"];
    NSDate* expectedExpiresTime = [NSDate dateWithTimeIntervalSinceNow:3600];
    XCTAssertNotNil(extExpires);
    XCTAssertTrue([expectedExpiresTime timeIntervalSinceDate:extExpires]<10); // 10 secs as tolerance

    // Purposely expire the AT
    atItem.expiresOn = [NSDate date];
    [cache addOrUpdateItem:atItem correlationId:nil error:&error];
    XCTAssertNil(error);

    // Test resiliency when response code 500 ... 599 happens
    ADTestURLResponse* response = [ADTestURLResponse requestURLString:[NSString stringWithFormat:@"%@/oauth2/token", TEST_AUTHORITY]
                                                    responseURLString:@"https://contoso.com"
                                                         responseCode:504
                                                     httpHeaderFields:@{ }
                                                     dictionaryAsJSON:@{ }];
    [response setRequestHeaders:[ADTestURLResponse defaultHeaders]];
    [response setUrlFormEncodedBody:@{ @"resource" : TEST_RESOURCE,
                                       @"client_id" : TEST_CLIENT_ID,
                                       @"grant_type" : @"refresh_token",
                                       MSID_OAUTH2_CLIENT_INFO: @"1",
                                       MSID_OAUTH2_SCOPE: MSID_OAUTH2_SCOPE_OPENID_VALUE,
                                       @"refresh_token" : TEST_REFRESH_TOKEN }];

    // Add the responsce twice because retry will happen
    [ADTestURLSession addResponse:response];
    [ADTestURLSession addResponse:response];

    expectation = [self expectationWithDescription:@"acquireTokenWithResource"];

    // Test whether valid stale access token is returned
    [context setExtendedLifetimeEnabled:YES];
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                               userId:TEST_USER_ID
                      completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         XCTAssertNil(result.error);
         XCTAssertTrue(result.extendedLifeTimeToken);
         XCTAssertEqualObjects(result.tokenCacheItem.accessToken, @"access token");
         XCTAssertEqualObjects(result.authority, TEST_AUTHORITY);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];

    XCTAssertTrue([ADTestURLSession noResponsesLeft]);
}

- (void)testResilencyTokenDeletion
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    id<ADALTokenCacheDataSource> cache = self.cacheDataSource;
    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithResource"];

    // Add an MRRT to the cache
    [cache addOrUpdateItem:[self adCreateMRRTCacheItem] correlationId:nil error:&error];
    XCTAssertNil(error);

    // Response with ext_expires_in value being 0
    [ADTestURLSession addResponse:[self adResponseRefreshToken:TEST_REFRESH_TOKEN
                                                        authority:TEST_AUTHORITY
                                                         resource:TEST_RESOURCE
                                                         clientId:TEST_CLIENT_ID
                                                    correlationId:TEST_CORRELATION_ID
                                                  newRefreshToken:@"refresh token"
                                                   newAccessToken:@"access token"
                                                    newIDToken:[self adDefaultIDToken]
                                                 additionalFields:@{ @"ext_expires_in" : @"0"}]];

    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                               userId:TEST_USER_ID
                      completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         XCTAssertNil(result.error);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];

    // Purposely expire the AT
    ADALTokenCacheKey* atKey = [ADALTokenCacheKey keyWithAuthority:TEST_AUTHORITY
                                                      resource:TEST_RESOURCE
                                                      clientId:TEST_CLIENT_ID
                                                         error:&error];
    XCTAssertNotNil(atKey);
    XCTAssertNil(error);

    ADALTokenCacheItem* atItem = [cache getItemWithKey:atKey userId:TEST_USER_ID correlationId:nil error:&error];
    XCTAssertNotNil(atItem);
    XCTAssertNil(error);

    atItem.expiresOn = [NSDate date];
    [cache addOrUpdateItem:atItem correlationId:nil error:&error];
    XCTAssertNil(error);

    // Delete the MRRT
    ADALTokenCacheKey* rtKey = [ADALTokenCacheKey keyWithAuthority:TEST_AUTHORITY
                                                      resource:nil
                                                      clientId:TEST_CLIENT_ID
                                                         error:&error];
    XCTAssertNotNil(rtKey);
    XCTAssertNil(error);

    ADALTokenCacheItem* rtItem = [cache getItemWithKey:rtKey userId:TEST_USER_ID correlationId:nil error:&error];
    XCTAssertNotNil(rtItem);
    XCTAssertNil(error);

    [cache removeItem:rtItem error:&error];
    XCTAssertNil(error);

    // Also remove common entry
    rtItem.authority = @"https://login.windows.net/common";
    [cache removeItem:rtItem error:&error];
    XCTAssertNil(error);

    // Clear MSAL cache, otherwise it will get into the way
    NSArray *allMSALItems = [_msalTokenCache allTokensWithContext:nil error:nil];

    for (MSIDBaseToken *token in allMSALItems)
    {
        if (token.credentialType == MSIDRefreshTokenType)
        {
            [_msalTokenCache validateAndRemoveRefreshToken:(MSIDRefreshToken *)token context:nil error:nil];
        }
    }

    expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    // AT is no longer valid neither in terms of expires_on and ext_expires_on
    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         // Request should fail because it's silent
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_SERVER_USER_INPUT_NEEDED);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];

    // Verify that the AT is removed from the cache
    NSArray* allItems = [cache allItems:&error];
    XCTAssertNil(error);

    XCTAssertTrue([ADTestURLSession noResponsesLeft]);
    XCTAssertEqual(allItems.count, 0);
}

- (void)testAcquireTokenInteractive_whenCapabilitiesAndClaimsPassed_shouldPassClaimsToServer
{
    NSString *authCode = @"i_am_a_auth_code";

    // Setup response
    NSString* requestUrlString = [NSString stringWithFormat:@"%@/oauth2/token", TEST_AUTHORITY];

    NSMutableDictionary* headers = [[ADTestURLResponse defaultHeaders] mutableCopy];
    headers[@"client-request-id"] = [TEST_CORRELATION_ID UUIDString];

    NSString *decodedClaims = @"{\"access_token\":{\"polids\":{\"values\":[\"5ce770ea-8690-4747-aa73-c5b3cd509cd4\"],\"essential\":true},\"xms_cc\":{\"values\":[\"testcap1\"]}}}";

    ADTestURLResponse* response =
    [ADTestURLResponse requestURLString:requestUrlString
                         requestHeaders:headers
                      requestParamsBody:@{ MSID_OAUTH2_GRANT_TYPE : MSID_OAUTH2_AUTHORIZATION_CODE,
                                           MSID_OAUTH2_CODE : authCode,
                                           MSID_OAUTH2_CLIENT_ID : TEST_CLIENT_ID,
                                           MSID_OAUTH2_REDIRECT_URI : TEST_REDIRECT_URL_STRING,
                                           MSID_OAUTH2_CLAIMS: decodedClaims,
                                           MSID_OAUTH2_CLIENT_INFO: @"1"
                                           }
                      responseURLString:@"https://contoso.com"
                           responseCode:200
                       httpHeaderFields:@{}
                       dictionaryAsJSON:@{ @"refresh_token" : TEST_REFRESH_TOKEN,
                                           @"access_token" : TEST_ACCESS_TOKEN,
                                           @"expires_in" : @"3600",
                                           @"resource" : TEST_RESOURCE,
                                           @"id_token" : [self adCreateUserInformation:TEST_USER_ID].rawIdToken }];

    [ADTestURLSession addResponse:response];

    ADALAuthenticationContext *context = [self getTestAuthenticationContext];
    XCTAssertNotNil(context);

    // Add a specific error as mock response to webview controller
    NSURL *endURL = [NSURL URLWithString:[NSString stringWithFormat:@"%@?code=%@", TEST_REDIRECT_URL_STRING, authCode]];
    MSIDWebviewResponse *aadResponse = [[MSIDWebAADAuthResponse alloc] initWithURL:endURL context:nil error:nil];
    [ADTestWebAuthController setResponse:aadResponse];

    __block XCTestExpectation *expectation = [self expectationWithDescription:@"acquire token"];

    NSString *claims = @"%7B%22access_token%22%3A%7B%22polids%22%3A%7B%22essential%22%3Atrue%2C%22values%22%3A%5B%225ce770ea-8690-4747-aa73-c5b3cd509cd4%22%5D%7D%7D%7D";

    context.clientCapabilities = @[@"testcap1"];
    context.correlationId = TEST_CORRELATION_ID;

    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                       promptBehavior:AD_PROMPT_AUTO
                       userIdentifier:nil
                 extraQueryParameters:nil
                               claims:claims
                      completionBlock:^(ADALAuthenticationResult *result) {

                          XCTAssertNotNil(result);
                          XCTAssertEqual(result.status, AD_SUCCEEDED);
                          [expectation fulfill];
    }];

    [self waitForExpectations:@[expectation] timeout:5.0];
}

- (void)testSkipCacheRequestParameters_whenSkipCacheIsNotSet_shouldNotSkipCache
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext *context = [self getTestAuthenticationContext];
    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireToken"];
    ADALRequestParameters *params = [ADALRequestParameters new];
    params.authority = context.authority;
    params.resource = TEST_RESOURCE;
    params.clientId = TEST_CLIENT_ID;
    params.redirectUri = TEST_REDIRECT_URL.absoluteString;
    params.identifier = [ADALUserIdentifier identifierWithId:TEST_USER_ID];
    params.extendedLifetime = NO;
    
    // Add a token item to return in the cache
    ADALTokenCacheItem* item = [self adCreateCacheItem];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];

    // No skipCache is set, cached item should be found

    ADALAuthenticationRequest *req = [ADALAuthenticationRequest requestWithContext:context
                                                                 requestParams:params
                                                                    tokenCache:self.tokenCache
                                                                         error:nil];
    [req acquireToken:@"123"
      completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         XCTAssertNotNil(result.tokenCacheItem);
         XCTAssertEqualObjects(result.authority, TEST_AUTHORITY);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}


- (void)testSkipCacheRequestParameters_whenSkipCacheIsSet_shouldSkipCache
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext *context = [self getTestAuthenticationContext];
    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireToken"];
    
    ADALRequestParameters *params = [ADALRequestParameters new];
    params.authority = context.authority;
    params.resource = TEST_RESOURCE;
    params.clientId = TEST_CLIENT_ID;
    params.redirectUri = TEST_REDIRECT_URL.absoluteString;
    params.identifier = [ADALUserIdentifier identifierWithId:TEST_USER_ID];
    params.extendedLifetime = NO;

    // Add a token item to return in the cache
    ADALTokenCacheItem* item = [self adCreateCacheItem];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];

    // skipCache is set, cache should be skipped and webview controller should be hit
    ADALAuthenticationRequest *req = [ADALAuthenticationRequest requestWithContext:context
                                                                 requestParams:params
                                                                    tokenCache:self.tokenCache
                                                                         error:nil];
    [req setSkipCache:YES];

    // Add a specific error as mock response to webview controller
    [ADTestWebAuthController setError:[NSError errorWithDomain:ADAuthenticationErrorDomain code:AD_ERROR_UI_NO_MAIN_VIEW_CONTROLLER userInfo:nil]];

    [req acquireToken:@"123"
      completionBlock:^(ADALAuthenticationResult *result)
     {
         // If webview is hit, the specific error code should be returned
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_UI_NO_MAIN_VIEW_CONTROLLER);
         XCTAssertNil(result.authority);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testAcquireToken_whenClaimsIsPassedViaOverloadedAcquireToken_andPromptAlways_shouldSkipCache
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithResource"];

    // Add a token item to cache
    ADALTokenCacheItem* item = [self adCreateCacheItem];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];

    // Add a specific error as mock response to webview controller
    [ADTestWebAuthController setError:[NSError errorWithDomain:ADAuthenticationErrorDomain code:AD_ERROR_UI_NO_MAIN_VIEW_CONTROLLER userInfo:nil]];

    // "claims" is passed in, cache should be skipped and webview controller should be hit
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                       promptBehavior:AD_PROMPT_ALWAYS
                       userIdentifier:[ADALUserIdentifier identifierWithId:TEST_USER_ID]
                 extraQueryParameters:nil
                               claims:@"%7B%22access_token%22%3A%7B%22polids%22%3A%7B%22essential%22%3Atrue%2C%22values%22%3A%5B%225ce770ea-8690-4747-aa73-c5b3cd509cd4%22%5D%7D%7D%7D"
                      completionBlock:^(ADALAuthenticationResult *result)
     {
         // If webview is hit, the specific error code should be returned
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_UI_NO_MAIN_VIEW_CONTROLLER);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testAcquireToken_whenCapabilitiesSet_andPromptAuto_andValidMRRT_shouldNotSkipAccessTokenCache
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    context.clientCapabilities = @[@"cp1"];

    ADALTokenCacheItem* item = [self adCreateATCacheItem];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);

    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithClaims"];

    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                       promptBehavior:AD_PROMPT_AUTO
                       userIdentifier:[ADALUserIdentifier identifierWithId:TEST_USER_ID]
                 extraQueryParameters:nil
                      completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         XCTAssertNil(result.error);
         XCTAssertEqualObjects(result.tokenCacheItem.accessToken, @"access token");

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testAcquireToken_whenCapabilitiesSet_andPromptAuto_andValidMRRT_andExpiredAccessToken_shouldSendCapabilitiesToServer
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    context.clientCapabilities = @[@"cp1", @"llt"];

    ADALTokenCacheItem* item = [self adCreateATCacheItem];
    item.expiresOn = [NSDate date];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);

    // Add an MRRT to the cache as well
    [self.cacheDataSource addOrUpdateItem:[self adCreateMRRTCacheItem] correlationId:nil error:&error];
    XCTAssertNil(error);

    // Add token response
    NSMutableDictionary* headers = [[ADTestURLResponse defaultHeaders] mutableCopy];
    headers[@"client-request-id"] = [TEST_CORRELATION_ID UUIDString];

    // Since claims on the token endpoint are sent as part of the body, ADAL doesn't double encode them
    // The unit tests are comparing the form we sent in ADAL against url decoded form
    NSString *decodedClaims = @"{\"access_token\":{\"xms_cc\":{\"values\":[\"cp1\",\"llt\"]}}}";

    ADTestURLResponse *response = [self adResponseRefreshToken:TEST_REFRESH_TOKEN
                                                     authority:TEST_AUTHORITY
                                                      resource:TEST_RESOURCE
                                                      clientId:TEST_CLIENT_ID
                                                requestHeaders:headers
                                                 correlationId:TEST_CORRELATION_ID
                                                  responseCode:200
                                               responseHeaders:nil
                                                  responseJson:@{ MSID_OAUTH2_REFRESH_TOKEN : @"new refresh token",
                                                                  MSID_OAUTH2_ACCESS_TOKEN : @"new access token",
                                                                  MSID_OAUTH2_RESOURCE : TEST_RESOURCE }
                                              useOpenidConnect:YES
                                                 requestParams:@{MSID_OAUTH2_CLAIMS : decodedClaims}];
    [ADTestURLSession addResponse:response];

    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithClaims"];

    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                       promptBehavior:AD_PROMPT_AUTO
                       userIdentifier:[ADALUserIdentifier identifierWithId:TEST_USER_ID]
                 extraQueryParameters:nil
                      completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         XCTAssertNil(result.error);
         XCTAssertEqualObjects(result.tokenCacheItem.accessToken, @"new access token");
         XCTAssertEqualObjects(result.tokenCacheItem.refreshToken, @"new refresh token");

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testAcquireToken_whenClaimsIsPassedViaOverloadedAcquireToken_andPromptAuto_andValidMRRT_shouldSkipAccessTokenCache
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];

    ADALTokenCacheItem* item = [self adCreateATCacheItem];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);

    // Add an MRRT to the cache as well
    [self.cacheDataSource addOrUpdateItem:[self adCreateMRRTCacheItem] correlationId:nil error:&error];
    XCTAssertNil(error);

    // Add token response
    NSMutableDictionary* headers = [[ADTestURLResponse defaultHeaders] mutableCopy];
    headers[@"client-request-id"] = [TEST_CORRELATION_ID UUIDString];

    NSString *testClaims = @"%7B%22access_token%22%3A%7B%22polids%22%3A%7B%22values%22%3A%5B%225ce770ea-8690-4747-aa73-c5b3cd509cd4%22%5D%2C%22essential%22%3Atrue%7D%7D%7D";
    // Since claims on the token endpoint are sent as part of the body, ADAL doesn't double encode them
    // The unit tests are comparing the form we sent in ADAL against url decoded form
    NSString *decodedClaims = @"{\"access_token\":{\"polids\":{\"values\":[\"5ce770ea-8690-4747-aa73-c5b3cd509cd4\"],\"essential\":true}}}";

    ADTestURLResponse *response = [self adResponseRefreshToken:TEST_REFRESH_TOKEN
                                                     authority:TEST_AUTHORITY
                                                      resource:TEST_RESOURCE
                                                      clientId:TEST_CLIENT_ID
                                                requestHeaders:headers
                                                 correlationId:TEST_CORRELATION_ID
                                                  responseCode:200
                                               responseHeaders:nil
                                                  responseJson:@{ MSID_OAUTH2_REFRESH_TOKEN : @"new refresh token",
                                                                  MSID_OAUTH2_ACCESS_TOKEN : @"new access token",
                                                                  MSID_OAUTH2_RESOURCE : TEST_RESOURCE }
                                              useOpenidConnect:YES
                                                 requestParams:@{MSID_OAUTH2_CLAIMS : decodedClaims}];
    [ADTestURLSession addResponse:response];

    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithClaims"];

    // "claims" is passed in, cache should be skipped
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                       promptBehavior:AD_PROMPT_AUTO
                       userIdentifier:[ADALUserIdentifier identifierWithId:TEST_USER_ID]
                 extraQueryParameters:nil
                               claims:testClaims
                      completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         XCTAssertNil(result.error);
         XCTAssertEqualObjects(result.tokenCacheItem.accessToken, @"new access token");
         XCTAssertEqualObjects(result.tokenCacheItem.refreshToken, @"new refresh token");

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testAcquireTokenSilent_whenUserMismatch_shouldContinueWithoutError
{
    XCTestExpectation* expectation = [self expectationWithDescription:@"requestToken"];
    ADALAuthenticationContext *context = [self getTestAuthenticationContext];
    
    ADALTokenCacheItem* item = [self adCreateMRRTCacheItem];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:nil];
    
    // Add a mock response returning tokens
    NSMutableDictionary* headers = [[ADTestURLResponse defaultHeaders] mutableCopy];
    headers[@"client-request-id"] = [TEST_CORRELATION_ID UUIDString];
    
    ADTestURLResponse *response = [self adResponseRefreshToken:TEST_REFRESH_TOKEN
                                                     authority:TEST_AUTHORITY
                                                      resource:TEST_RESOURCE
                                                      clientId:TEST_CLIENT_ID
                                                requestHeaders:headers
                                                 correlationId:TEST_CORRELATION_ID
                                                  responseCode:200
                                               responseHeaders:nil
                                                  responseJson:@{ MSID_OAUTH2_REFRESH_TOKEN : @"new refresh token",
                                                                  MSID_OAUTH2_ACCESS_TOKEN : @"new access token",
                                                                  MSID_OAUTH2_RESOURCE : TEST_RESOURCE,
                                                                  @"id_token" : [self adCreateUserInformation:@"someotheruser@contoso.com"].rawIdToken
                                                                  }
                                              useOpenidConnect:YES
                                                 requestParams:nil];
    [ADTestURLSession addResponse:response];
    
    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                                     claims:nil
                            completionBlock:^(ADALAuthenticationResult *result) {
                                
                                XCTAssertNotNil(result);
                                XCTAssertEqual(result.status, AD_SUCCEEDED);
                                XCTAssertNil(result.error);
                                XCTAssertNotNil(result.tokenCacheItem);
                                
                                [expectation fulfill];
                            }];
    
    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testAcquireTokenSilent_whenCapabilitiesSet_andValidMRRT_shouldNotSkipAccessTokenCache
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    context.clientCapabilities = @[@"cp1", @"llt"];

    ADALTokenCacheItem* item = [self adCreateATCacheItem];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);

    // Add an MRRT to the cache as well
    [self.cacheDataSource addOrUpdateItem:[self adCreateMRRTCacheItem] correlationId:nil error:&error];
    XCTAssertNil(error);

    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithClaims"];

    // "claims" is passed in, cache should be skipped
    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADALAuthenticationResult *result) {

                                    XCTAssertNotNil(result);
                                    XCTAssertEqual(result.status, AD_SUCCEEDED);
                                    XCTAssertNil(result.error);
                                    XCTAssertEqualObjects(result.tokenCacheItem.accessToken, @"access token");

                                    [expectation fulfill];
                            }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testAcquireTokenSilent_whenCapabilitiesSet_andValidMRRT_andExpiredAccessToken_shouldSendCapabilitiesToServer
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    context.clientCapabilities = @[@"cp1", @"llt"];

    ADALTokenCacheItem* item = [self adCreateATCacheItem];
    item.expiresOn = [NSDate date];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];

    XCTAssertNil(error);

    // Add an MRRT to the cache as well
    [self.cacheDataSource addOrUpdateItem:[self adCreateMRRTCacheItem] correlationId:nil error:&error];
    XCTAssertNil(error);

    // Add token response
    NSMutableDictionary* headers = [[ADTestURLResponse defaultHeaders] mutableCopy];
    headers[@"client-request-id"] = [TEST_CORRELATION_ID UUIDString];

    NSString *decodedClaims = @"{\"access_token\":{\"xms_cc\":{\"values\":[\"cp1\",\"llt\"]}}}";

    ADTestURLResponse *response = [self adResponseRefreshToken:TEST_REFRESH_TOKEN
                                                     authority:TEST_AUTHORITY
                                                      resource:TEST_RESOURCE
                                                      clientId:TEST_CLIENT_ID
                                                requestHeaders:headers
                                                 correlationId:TEST_CORRELATION_ID
                                                  responseCode:200
                                               responseHeaders:nil
                                                  responseJson:@{ MSID_OAUTH2_REFRESH_TOKEN : @"new refresh token",
                                                                  MSID_OAUTH2_ACCESS_TOKEN : @"new access token",
                                                                  MSID_OAUTH2_RESOURCE : TEST_RESOURCE }
                                              useOpenidConnect:YES
                                                 requestParams:@{MSID_OAUTH2_CLAIMS : decodedClaims}];
    [ADTestURLSession addResponse:response];

    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithClaims"];

    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADALAuthenticationResult *result) {

                                XCTAssertNotNil(result);
                                XCTAssertEqual(result.status, AD_SUCCEEDED);
                                XCTAssertNil(result.error);
                                XCTAssertEqualObjects(result.tokenCacheItem.accessToken, @"new access token");
                                XCTAssertEqualObjects(result.tokenCacheItem.refreshToken, @"new refresh token");

                                [expectation fulfill];
                            }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testAcquireTokenSilent_whenCapabilitiesSet_andValidMRRT_andCustomClaimsPassed_shouldSkipAccessTokenCache
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    context.clientCapabilities = @[@"llt"];

    ADALTokenCacheItem* item = [self adCreateATCacheItem];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);

    // Add an MRRT to the cache as well
    [self.cacheDataSource addOrUpdateItem:[self adCreateMRRTCacheItem] correlationId:nil error:&error];
    XCTAssertNil(error);

    // Add token response
    NSMutableDictionary* headers = [[ADTestURLResponse defaultHeaders] mutableCopy];
    headers[@"client-request-id"] = [TEST_CORRELATION_ID UUIDString];

    NSString *testClaims = @"%7B%22access_token%22%3A%7B%22xms_cc%22%3A%5B%22llt%22%5D%7D%2C%22id_token%22%3A%7B%22polids%22%3A%7B%22values%22%3A%5B%22d77e91f0-fc60-45e4-97b8-14a1337faa28%22%5D%2C%22essential%22%3Atrue%7D%7D%7D";
    // Since claims on the token endpoint are sent as part of the body, ADAL doesn't double encode them
    // The unit tests are comparing the form we sent in ADAL against url decoded form
    NSString *decodedClaims = @"{\"access_token\":{\"xms_cc\":{\"values\":[\"llt\"]}},\"id_token\":{\"polids\":{\"values\":[\"d77e91f0-fc60-45e4-97b8-14a1337faa28\"],\"essential\":true}}}";

    ADTestURLResponse *response = [self adResponseRefreshToken:TEST_REFRESH_TOKEN
                                                     authority:TEST_AUTHORITY
                                                      resource:TEST_RESOURCE
                                                      clientId:TEST_CLIENT_ID
                                                requestHeaders:headers
                                                 correlationId:TEST_CORRELATION_ID
                                                  responseCode:200
                                               responseHeaders:nil
                                                  responseJson:@{ MSID_OAUTH2_REFRESH_TOKEN : @"new refresh token",
                                                                  MSID_OAUTH2_ACCESS_TOKEN : @"new access token",
                                                                  MSID_OAUTH2_RESOURCE : TEST_RESOURCE }
                                              useOpenidConnect:YES
                                                 requestParams:@{MSID_OAUTH2_CLAIMS : decodedClaims}];
    [ADTestURLSession addResponse:response];

    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithClaims"];

    // "claims" is passed in, cache should be skipped
    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                                     claims:testClaims
                            completionBlock:^(ADALAuthenticationResult *result) {

                                XCTAssertNotNil(result);
                                XCTAssertEqual(result.status, AD_SUCCEEDED);
                                XCTAssertNil(result.error);
                                XCTAssertEqualObjects(result.tokenCacheItem.accessToken, @"new access token");
                                XCTAssertEqualObjects(result.tokenCacheItem.refreshToken, @"new refresh token");

                                [expectation fulfill];
                            }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testAcquireTokenSilent_whenClaimsIsPassedViaOverloadedAcquireToken_andValidMRRT_shouldSkipAccessTokenCache
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];

    ADALTokenCacheItem* item = [self adCreateATCacheItem];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);

    // Add an MRRT to the cache as well
    [self.cacheDataSource addOrUpdateItem:[self adCreateMRRTCacheItem] correlationId:nil error:&error];
    XCTAssertNil(error);

    // Add token response
    NSMutableDictionary* headers = [[ADTestURLResponse defaultHeaders] mutableCopy];
    headers[@"client-request-id"] = [TEST_CORRELATION_ID UUIDString];

    NSString *testClaims = @"%7B%22access_token%22%3A%7B%22polids%22%3A%7B%22values%22%3A%5B%225ce770ea-8690-4747-aa73-c5b3cd509cd4%22%5D%2C%22essential%22%3Atrue%7D%7D%7D";
    // Since claims on the token endpoint are sent as part of the body, ADAL doesn't double encode them
    // The unit tests are comparing the form we sent in ADAL against url decoded form
    NSString *decodedClaims = @"{\"access_token\":{\"polids\":{\"values\":[\"5ce770ea-8690-4747-aa73-c5b3cd509cd4\"],\"essential\":true}}}";

    ADTestURLResponse *response = [self adResponseRefreshToken:TEST_REFRESH_TOKEN
                                                     authority:TEST_AUTHORITY
                                                      resource:TEST_RESOURCE
                                                      clientId:TEST_CLIENT_ID
                                                requestHeaders:headers
                                                 correlationId:TEST_CORRELATION_ID
                                                  responseCode:200
                                               responseHeaders:nil
                                                  responseJson:@{ MSID_OAUTH2_REFRESH_TOKEN : @"new refresh token",
                                                                  MSID_OAUTH2_ACCESS_TOKEN : @"new access token",
                                                                  MSID_OAUTH2_RESOURCE : TEST_RESOURCE }
                                              useOpenidConnect:YES
                                                 requestParams:@{MSID_OAUTH2_CLAIMS : decodedClaims}];
    [ADTestURLSession addResponse:response];

    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithClaims"];

    // "claims" is passed in, cache should be skipped
    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                                     claims:testClaims
                            completionBlock:^(ADALAuthenticationResult *result) {

                                XCTAssertNotNil(result);
                                XCTAssertEqual(result.status, AD_SUCCEEDED);
                                XCTAssertNil(result.error);
                                XCTAssertEqualObjects(result.tokenCacheItem.accessToken, @"new access token");
                                XCTAssertEqualObjects(result.tokenCacheItem.refreshToken, @"new refresh token");

                                [expectation fulfill];
    }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testAcquireTokenSilent_whenClaimsIsPassedViaOverloadedAcquireToken_andInValidMRRT_shouldFailWithInputNeededError
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];

    ADALTokenCacheItem* item = [self adCreateATCacheItem];
    item.expiresOn = [NSDate date];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);

    // Add an MRRT to the cache as well
    [self.cacheDataSource addOrUpdateItem:[self adCreateMRRTCacheItem] correlationId:nil error:&error];
    XCTAssertNil(error);

    // Add token response
    NSString *testClaims = @"%7B%22access_token%22%3A%7B%22polids%22%3A%7B%22values%22%3A%5B%225ce770ea-8690-4747-aa73-c5b3cd509cd4%22%5D%2C%22essential%22%3Atrue%7D%7D%7D";
    // Since claims on the token endpoint are sent as part of the body, ADAL doesn't double encode them
    // The unit tests are comparing the form we sent in ADAL against url decoded form
    NSString *decodedClaims = @"{\"access_token\":{\"polids\":{\"values\":[\"5ce770ea-8690-4747-aa73-c5b3cd509cd4\"],\"essential\":true}}}";

    ADTestURLResponse *response = [self adResponseBadRefreshToken:TEST_REFRESH_TOKEN
                                                        authority:TEST_AUTHORITY
                                                         resource:TEST_RESOURCE
                                                         clientId:TEST_CLIENT_ID
                                                       oauthError:@"interaction_required"
                                                    oauthSubError:nil
                                                    correlationId:TEST_CORRELATION_ID
                                                    requestParams:@{MSID_OAUTH2_CLAIMS : decodedClaims}];

    [ADTestURLSession addResponse:response];

    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithClaims"];

    // "claims" is passed in, cache should be skipped
    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                                     claims:testClaims
                            completionBlock:^(ADALAuthenticationResult *result) {

                                XCTAssertNotNil(result);
                                XCTAssertEqual(result.status, AD_FAILED);
                                XCTAssertNotNil(result.error);
                                XCTAssertEqual(result.error.code, AD_ERROR_SERVER_USER_INPUT_NEEDED);

                                [expectation fulfill];
                            }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testAcquireToken_whenClaimsIsPassedViaOverloadedAcquireToken_andPromptAuto_andInValidMRRT_shouldSkipAccessTokenCache_andShowUI
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];

    ADALTokenCacheItem* item = [self adCreateATCacheItem];
    item.expiresOn = [NSDate date];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);

    // Add an MRRT to the cache as well
    [self.cacheDataSource addOrUpdateItem:[self adCreateMRRTCacheItem] correlationId:nil error:&error];
    XCTAssertNil(error);

    NSString *testClaims = @"%7B%22access_token%22%3A%7B%22polids%22%3A%7B%22values%22%3A%5B%225ce770ea-8690-4747-aa73-c5b3cd509cd4%22%5D%2C%22essential%22%3Atrue%7D%7D%7D";
    // Since claims on the token endpoint are sent as part of the body, ADAL doesn't double encode them
    // The unit tests are comparing the form we sent in ADAL against url decoded form
    NSString *decodedClaims = @"{\"access_token\":{\"polids\":{\"values\":[\"5ce770ea-8690-4747-aa73-c5b3cd509cd4\"],\"essential\":true}}}";

    // Add token response to return interaction required
    ADTestURLResponse *tokenResponse =
    [self adResponseBadRefreshToken:TEST_REFRESH_TOKEN
                          authority:TEST_AUTHORITY
                           resource:TEST_RESOURCE
                           clientId:TEST_CLIENT_ID
                         oauthError:@"interaction_required"
                      oauthSubError:nil
                      correlationId:TEST_CORRELATION_ID
                      requestParams:@{MSID_OAUTH2_CLAIMS : decodedClaims}];

    [ADTestURLSession addResponse:tokenResponse];

    // Add a specific error as mock response to webview controller
    [ADTestWebAuthController setError:[NSError errorWithDomain:ADAuthenticationErrorDomain code:AD_ERROR_UI_NO_MAIN_VIEW_CONTROLLER userInfo:nil]];

    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithClaims"];

    // "claims" is passed in, cache should be skipped
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                       promptBehavior:AD_PROMPT_AUTO
                       userIdentifier:[ADALUserIdentifier identifierWithId:TEST_USER_ID]
                 extraQueryParameters:nil
                               claims:testClaims
                      completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_UI_NO_MAIN_VIEW_CONTROLLER);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testAcquireToken_whenClaimsIsNotProperlyEncoded_shouldReturnError
{
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithResource"];

    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                       promptBehavior:AD_PROMPT_AUTO
                       userIdentifier:[ADALUserIdentifier identifierWithId:TEST_USER_ID]
                 extraQueryParameters:nil
                               claims:@"{\"access_token\":{\"polids\":{\"values\":[\"5ce770ea-8690-4747-aa73-c5b3cd509cd4\"],\"essential\":true}}}"
                      completionBlock:^(ADALAuthenticationResult *result)
     {
         // Error code AD_ERROR_DEVELOPER_INVALID_ARGUMENT should be returned
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testAcquireToken_whenClaimsIsNotProperJSON_shouldReturnError
{
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithResource"];

    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                       promptBehavior:AD_PROMPT_AUTO
                       userIdentifier:[ADALUserIdentifier identifierWithId:TEST_USER_ID]
                 extraQueryParameters:nil
                               claims:@"%7BI%27m%20not%20JSON%7D"
                      completionBlock:^(ADALAuthenticationResult *result)
     {
         // Error code AD_ERROR_DEVELOPER_INVALID_ARGUMENT should be returned
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);
         XCTAssertEqualObjects(result.error.errorDetails, @"claims is not proper JSON. Please make sure it is correct JSON claims parameter.");

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testAcquireToken_whenClaimsIsNil_shouldNotSkipCache
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithResource"];

    // Add a token item to return in the cache
    ADALTokenCacheItem* item = [self adCreateCacheItem];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];

    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                       promptBehavior:AD_PROMPT_AUTO
                       userIdentifier:[ADALUserIdentifier identifierWithId:TEST_USER_ID]
                 extraQueryParameters:nil
                               claims:nil
                      completionBlock:^(ADALAuthenticationResult *result)
     {
         //Token in cache should be found
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         XCTAssertNotNil(result.tokenCacheItem);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testAcquireToken_whenClaimsIsEmpty_shouldNotSkipCache
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithResource"];

    // Add a token item to return in the cache
    ADALTokenCacheItem* item = [self adCreateCacheItem];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];

    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                       promptBehavior:AD_PROMPT_AUTO
                       userIdentifier:[ADALUserIdentifier identifierWithId:TEST_USER_ID]
                 extraQueryParameters:nil
                               claims:@""
                      completionBlock:^(ADALAuthenticationResult *result)
     {
         //Token in cache should be found
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         XCTAssertNotNil(result.tokenCacheItem);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}


- (void)testAcquireToken_whenDuplicateClaimsIsPassedInEQP_shouldReturnError
{
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithResource"];

    // Add a specific error as mock response to webview controller
    [ADTestWebAuthController setError:[NSError errorWithDomain:ADAuthenticationErrorDomain code:AD_ERROR_UI_NO_MAIN_VIEW_CONTROLLER userInfo:nil]];
    
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                       promptBehavior:AD_PROMPT_AUTO
                       userIdentifier:[ADALUserIdentifier identifierWithId:TEST_USER_ID]
                 extraQueryParameters:@"claims=%7B%22access_token%22%3A%7B%22polids%22%3A%7B%22essential%22%3Atrue%2C%22values%22%3A%5B%225ce770ea-8690-4747-aa73-c5b3cd509cd4%22%5D%7D%7D%7D"
                               claims:@"%7B%22access_token%22%3A%7B%22polids%22%3A%7B%22essential%22%3Atrue%2C%22values%22%3A%5B%225ce770ea-8690-4747-aa73-c5b3cd509cd4%22%5D%7D%7D%7D"
                      completionBlock:^(ADALAuthenticationResult *result)
     {
         //Error code AD_ERROR_DEVELOPER_INVALID_ARGUMENT should be returned
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testMRRT_whenGetting429ThrottledResponse_shouldReturnHttpHeaders
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenWithResource"];

    // Add an MRRT to the cache
    ADALTokenCacheItem* mrrtItem = [self adCreateMRRTCacheItem];
    [self.cacheDataSource addOrUpdateItem:mrrtItem correlationId:nil error:&error];
    XCTAssertNil(error);

    // Set up the mock connection to simulate a 429 throttled error
    NSString* requestURLString = TEST_AUTHORITY "/oauth2/token";
    
    ADTestURLResponse* response = [ADTestURLResponse requestURLString:requestURLString
                                                    responseURLString:@"https://contoso.com"
                                                         responseCode:429
                                                     httpHeaderFields:@{@"Retry-After":@"120"}
                                                     dictionaryAsJSON:nil];
    [response setRequestHeaders:[ADTestURLResponse defaultHeaders]];
    [response setUrlFormEncodedBody:@{ @"resource" : TEST_RESOURCE,
                                       @"client_id" : TEST_CLIENT_ID,
                                       @"grant_type" : @"refresh_token",
                                       MSID_OAUTH2_CLIENT_INFO: @"1",
                                       MSID_OAUTH2_SCOPE: MSID_OAUTH2_SCOPE_OPENID_VALUE,
                                       @"refresh_token" : TEST_REFRESH_TOKEN }];

    [ADTestURLSession addResponse:response];

    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                               userId:TEST_USER_ID
                      completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertNotNil(result.error.userInfo[ADHTTPHeadersKey]);
         XCTAssertEqualObjects(result.error.userInfo[ADHTTPHeadersKey][@"Retry-After"], @"120");
         XCTAssertNil(result.authority);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testAcquireToken_whenRefreshTokenIsNotPassedIn_shouldReturnError
{
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithRefreshToken"];

    NSString *refreshToken = nil;
    [context acquireTokenWithRefreshToken:refreshToken
                                 resource:TEST_RESOURCE
                                 clientId:TEST_CLIENT_ID
                              redirectUri:TEST_REDIRECT_URL
                      completionBlock:^(ADALAuthenticationResult *result)
     {
         //Error code AD_ERROR_DEVELOPER_INVALID_ARGUMENT should be returned
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testAcquireToken_whenRefreshTokenIsPassedIn_shouldSkipCacheAndUseTheGivenRefreshToken
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithRefreshToken"];

    // Add an AT and an MRRT to the cache
    [self.cacheDataSource addOrUpdateItem:[self adCreateATCacheItem] correlationId:nil error:&error];
    XCTAssertNil(error);
    [self.cacheDataSource addOrUpdateItem:[self adCreateMRRTCacheItem] correlationId:nil error:&error];
    XCTAssertNil(error);

    // the request should be using refresh token from developer
    ADTestURLResponse *response = [self adResponseRefreshToken:@"refresh token from developer"
                                                     authority:TEST_AUTHORITY
                                                      resource:TEST_RESOURCE
                                                      clientId:TEST_CLIENT_ID
                                                 correlationId:TEST_CORRELATION_ID
                                               newRefreshToken:@"refresh token from server"
                                                newAccessToken:@"access token from server"
                                                    newIDToken:[self adDefaultIDToken]];

    // explicitly set scope=open as the required field in request body
    [response setUrlFormEncodedBody:@{ MSID_OAUTH2_GRANT_TYPE : @"refresh_token",
                                       MSID_OAUTH2_REFRESH_TOKEN : @"refresh token from developer",
                                       MSID_OAUTH2_RESOURCE : TEST_RESOURCE,
                                       MSID_OAUTH2_CLIENT_ID : TEST_CLIENT_ID,
                                       MSID_OAUTH2_SCOPE : MSID_OAUTH2_SCOPE_OPENID_VALUE,
                                       MSID_OAUTH2_CLIENT_INFO: @"1"
                                       }];

    [ADTestURLSession addResponse:response];

    [context acquireTokenWithRefreshToken:@"refresh token from developer"
                                 resource:TEST_RESOURCE
                                 clientId:TEST_CLIENT_ID
                              redirectUri:TEST_REDIRECT_URL
                          completionBlock:^(ADALAuthenticationResult *result)
     {
         //we should skip cache and hit network and get back new access token
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         XCTAssertNil(result.error);
         XCTAssertEqualObjects(result.authority, TEST_AUTHORITY);
         XCTAssertEqualObjects(result.accessToken, @"access token from server");
         XCTAssertEqualObjects(result.tokenCacheItem.refreshToken, @"refresh token from server");
         XCTAssertEqualObjects(result.tokenCacheItem.resource, TEST_RESOURCE);
         XCTAssertEqualObjects(result.tokenCacheItem.clientId, TEST_CLIENT_ID);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testAcquireToken_whenRefreshTokenIsPassedIn_shouldStoreTokensIfSucceed
{
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithRefreshToken"];

    // the request should be using refresh token from developer
    ADTestURLResponse *response = [self adResponseRefreshToken:@"refresh token from developer"
                                                     authority:TEST_AUTHORITY
                                                      resource:TEST_RESOURCE
                                                      clientId:TEST_CLIENT_ID
                                                 correlationId:TEST_CORRELATION_ID
                                               newRefreshToken:@"refresh token from server"
                                                newAccessToken:@"access token from server"
                                                    newIDToken:[self adDefaultIDToken]];

    // explicitly set scope=open as the required field in request body
    [response setUrlFormEncodedBody:@{ MSID_OAUTH2_GRANT_TYPE : @"refresh_token",
                                       MSID_OAUTH2_REFRESH_TOKEN : @"refresh token from developer",
                                       MSID_OAUTH2_RESOURCE : TEST_RESOURCE,
                                       MSID_OAUTH2_CLIENT_ID : TEST_CLIENT_ID,
                                       MSID_OAUTH2_SCOPE : MSID_OAUTH2_SCOPE_OPENID_VALUE,
                                       MSID_OAUTH2_CLIENT_INFO: @"1"
                                       }];

    [ADTestURLSession addResponse:response];

    [context acquireTokenWithRefreshToken:@"refresh token from developer"
                                 resource:TEST_RESOURCE
                                 clientId:TEST_CLIENT_ID
                              redirectUri:TEST_REDIRECT_URL
                          completionBlock:^(ADALAuthenticationResult *result)
     {
         //we should skip cache and hit network and get back new access token
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         XCTAssertEqualObjects(result.accessToken, @"access token from server");

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];

    // make a silent call again to see if tokens are stored properly
    expectation = [self expectationWithDescription:@"acquireTokenSilent"];

    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         XCTAssertNil(result.error);
         XCTAssertEqualObjects(result.authority, TEST_AUTHORITY);
         XCTAssertEqualObjects(result.accessToken, @"access token from server");
         XCTAssertEqualObjects(result.tokenCacheItem.resource, TEST_RESOURCE);
         XCTAssertEqualObjects(result.tokenCacheItem.clientId, TEST_CLIENT_ID);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testAcquireToken_whenRefreshTokenRejected_shouldNotDeleteTokenInCacheWithSameCacheKey
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithRefreshToken"];

    // Add an MRRT to the cache
    [self.cacheDataSource addOrUpdateItem:[self adCreateMRRTCacheItem] correlationId:nil error:&error];
    XCTAssertNil(error);

    // Network Response to reject developer's refresh token
    ADTestURLResponse *response = [self adResponseBadRefreshToken:@"refresh token from developer"
                                                        authority:TEST_AUTHORITY
                                                         resource:TEST_RESOURCE
                                                         clientId:TEST_CLIENT_ID
                                                       oauthError:@"invalid_grant"
                                                    oauthSubError:nil
                                                    correlationId:TEST_CORRELATION_ID
                                                    requestParams:nil];
    
    // explicitly set scope=open as the required field in request body
    [response setUrlFormEncodedBody:@{ MSID_OAUTH2_GRANT_TYPE : @"refresh_token",
                                       MSID_OAUTH2_REFRESH_TOKEN : @"refresh token from developer",
                                       MSID_OAUTH2_RESOURCE : TEST_RESOURCE,
                                       MSID_OAUTH2_CLIENT_ID : TEST_CLIENT_ID,
                                       MSID_OAUTH2_SCOPE : MSID_OAUTH2_SCOPE_OPENID_VALUE,
                                       MSID_OAUTH2_CLIENT_INFO: @"1"
                                       }];

    [ADTestURLSession addResponse:response];

    [context acquireTokenWithRefreshToken:@"refresh token from developer"
                                 resource:TEST_RESOURCE
                                 clientId:TEST_CLIENT_ID
                              redirectUri:TEST_REDIRECT_URL
                          completionBlock:^(ADALAuthenticationResult *result)
     {
         // We should fail with "invalid_grant" error
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertEqualObjects(result.error.protocolCode, @"invalid_grant");
         XCTAssertEqualObjects(result.error.domain, ADOAuthServerErrorDomain);
         XCTAssertEqual(result.error.code, AD_ERROR_SERVER_REFRESH_TOKEN_REJECTED);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];

    // Refresh token in cache should not be deleted because the token itself is different from
    // the one provided by developer
    ADALTokenCacheItem *rtInCache = [self.cacheDataSource getItemWithKey:[self.adCreateMRRTCacheItem extractKey:nil]  userId:TEST_USER_ID correlationId:TEST_CORRELATION_ID error:nil];
    XCTAssertNotNil(rtInCache);
}

- (void)testAcquireTokenWithRefreshTokenAndUserId_whenRefreshTokenIsNotPassedIn_shouldReturnError
{
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithRefreshToken"];
    
    NSString *refreshToken = nil;
    [context acquireTokenWithRefreshToken:refreshToken
                                 resource:TEST_RESOURCE
                                 clientId:TEST_CLIENT_ID
                              redirectUri:TEST_REDIRECT_URL
                                   userId:TEST_USER_ID
                          completionBlock:^(ADALAuthenticationResult *result)
     {
         //Error code AD_ERROR_DEVELOPER_INVALID_ARGUMENT should be returned
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testAcquireTokenWithRefreshTokenAndUserId_whenRefreshTokenIsPassedIn_shouldSkipCacheAndUseTheGivenRefreshToken
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithRefreshToken"];

    // Add an AT and an MRRT to the cache
    [self.cacheDataSource addOrUpdateItem:[self adCreateATCacheItem] correlationId:nil error:&error];
    XCTAssertNil(error);
    [self.cacheDataSource addOrUpdateItem:[self adCreateMRRTCacheItem] correlationId:nil error:&error];
    XCTAssertNil(error);

    // the request should be using refresh token from developer
    ADTestURLResponse *response = [self adResponseRefreshToken:@"refresh token from developer"
                                                     authority:TEST_AUTHORITY
                                                      resource:TEST_RESOURCE
                                                      clientId:TEST_CLIENT_ID
                                                 correlationId:TEST_CORRELATION_ID
                                               newRefreshToken:@"refresh token from server"
                                                newAccessToken:@"access token from server"
                                                    newIDToken:[self adDefaultIDToken]];

    // explicitly set scope=open as the required field in request body
    [response setUrlFormEncodedBody:@{ MSID_OAUTH2_GRANT_TYPE : @"refresh_token",
                                       MSID_OAUTH2_REFRESH_TOKEN : @"refresh token from developer",
                                       MSID_OAUTH2_RESOURCE : TEST_RESOURCE,
                                       MSID_OAUTH2_CLIENT_ID : TEST_CLIENT_ID,
                                       MSID_OAUTH2_SCOPE : MSID_OAUTH2_SCOPE_OPENID_VALUE,
                                       MSID_OAUTH2_CLIENT_INFO: @"1"
                                       }];

    [ADTestURLSession addResponse:response];

    [context acquireTokenWithRefreshToken:@"refresh token from developer"
                                 resource:TEST_RESOURCE
                                 clientId:TEST_CLIENT_ID
                              redirectUri:TEST_REDIRECT_URL
                                   userId:TEST_USER_ID
                          completionBlock:^(ADALAuthenticationResult *result)
     {
         //we should skip cache and hit network and get back new access token
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         XCTAssertNil(result.error);
         XCTAssertEqualObjects(result.authority, TEST_AUTHORITY);
         XCTAssertEqualObjects(result.accessToken, @"access token from server");
         XCTAssertEqualObjects(result.tokenCacheItem.refreshToken, @"refresh token from server");
         XCTAssertEqualObjects(result.tokenCacheItem.resource, TEST_RESOURCE);
         XCTAssertEqualObjects(result.tokenCacheItem.clientId, TEST_CLIENT_ID);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testAcquireTokenWithRefreshTokenAndUserId_whenRefreshTokenIsPassedIn_shouldStoreTokensIfSucceed
{
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithRefreshToken"];

    // the request should be using refresh token from developer
    ADTestURLResponse *response = [self adResponseRefreshToken:@"refresh token from developer"
                                                     authority:TEST_AUTHORITY
                                                      resource:TEST_RESOURCE
                                                      clientId:TEST_CLIENT_ID
                                                 correlationId:TEST_CORRELATION_ID
                                               newRefreshToken:@"refresh token from server"
                                                newAccessToken:@"access token from server"
                                                    newIDToken:[self adDefaultIDToken]];

    // explicitly set scope=open as the required field in request body
    [response setUrlFormEncodedBody:@{ MSID_OAUTH2_GRANT_TYPE : @"refresh_token",
                                       MSID_OAUTH2_REFRESH_TOKEN : @"refresh token from developer",
                                       MSID_OAUTH2_RESOURCE : TEST_RESOURCE,
                                       MSID_OAUTH2_CLIENT_ID : TEST_CLIENT_ID,
                                       MSID_OAUTH2_SCOPE : MSID_OAUTH2_SCOPE_OPENID_VALUE,
                                       MSID_OAUTH2_CLIENT_INFO: @"1"
                                       }];

    [ADTestURLSession addResponse:response];

    [context acquireTokenWithRefreshToken:@"refresh token from developer"
                                 resource:TEST_RESOURCE
                                 clientId:TEST_CLIENT_ID
                              redirectUri:TEST_REDIRECT_URL
                                   userId:TEST_USER_ID
                          completionBlock:^(ADALAuthenticationResult *result)
     {
         //we should skip cache and hit network and get back new access token
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         XCTAssertEqualObjects(result.accessToken, @"access token from server");

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];

    // make a silent call again to see if tokens are stored properly
    expectation = [self expectationWithDescription:@"acquireTokenSilent"];

    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         XCTAssertNil(result.error);
         XCTAssertEqualObjects(result.authority, TEST_AUTHORITY);
         XCTAssertEqualObjects(result.accessToken, @"access token from server");
         XCTAssertEqualObjects(result.tokenCacheItem.resource, TEST_RESOURCE);
         XCTAssertEqualObjects(result.tokenCacheItem.clientId, TEST_CLIENT_ID);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testAcquireTokenWithRefreshTokenAndUserId_whenRefreshTokenRejected_shouldNotDeleteTokenInCacheWithSameCacheKey
{
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithRefreshToken"];

    // Add an MRRT to the cache
    [self.cacheDataSource addOrUpdateItem:[self adCreateMRRTCacheItem] correlationId:nil error:&error];
    XCTAssertNil(error);

    // Network Response to reject developer's refresh token
    ADTestURLResponse *response = [self adResponseBadRefreshToken:@"refresh token from developer"
                                                        authority:TEST_AUTHORITY
                                                         resource:TEST_RESOURCE
                                                         clientId:TEST_CLIENT_ID
                                                       oauthError:@"invalid_grant"
                                                    oauthSubError:nil
                                                    correlationId:TEST_CORRELATION_ID
                                                    requestParams:nil];

    // explicitly set scope=open as the required field in request body
    [response setUrlFormEncodedBody:@{ MSID_OAUTH2_GRANT_TYPE : @"refresh_token",
                                       MSID_OAUTH2_REFRESH_TOKEN : @"refresh token from developer",
                                       MSID_OAUTH2_RESOURCE : TEST_RESOURCE,
                                       MSID_OAUTH2_CLIENT_ID : TEST_CLIENT_ID,
                                       MSID_OAUTH2_SCOPE : MSID_OAUTH2_SCOPE_OPENID_VALUE,
                                       MSID_OAUTH2_CLIENT_INFO: @"1"
                                       }];

    [ADTestURLSession addResponse:response];

    [context acquireTokenWithRefreshToken:@"refresh token from developer"
                                 resource:TEST_RESOURCE
                                 clientId:TEST_CLIENT_ID
                              redirectUri:TEST_REDIRECT_URL
                                   userId:TEST_USER_ID
                          completionBlock:^(ADALAuthenticationResult *result)
     {
         // We should fail with "invalid_grant" error
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertEqualObjects(result.error.protocolCode, @"invalid_grant");
         XCTAssertEqualObjects(result.error.domain, ADOAuthServerErrorDomain);
         XCTAssertEqual(result.error.code, AD_ERROR_SERVER_REFRESH_TOKEN_REJECTED);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];

    // Refresh token in cache should not be deleted because the token itself is different from
    // the one provided by developer
    ADALTokenCacheItem *rtInCache = [self.cacheDataSource getItemWithKey:[self.adCreateMRRTCacheItem extractKey:nil]  userId:TEST_USER_ID correlationId:TEST_CORRELATION_ID error:nil];
    XCTAssertNotNil(rtInCache);
}

- (void)testAcquireTokenWithRefreshTokenAndUserId_whenRefreshTokenAndUserIdMismatch_shouldSucceed
{
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithRefreshToken"];

    // the request should be using refresh token from developer
    ADTestURLResponse *response = [self adResponseRefreshToken:@"refresh token from developer"
                                                     authority:TEST_AUTHORITY
                                                      resource:TEST_RESOURCE
                                                      clientId:TEST_CLIENT_ID
                                                 correlationId:TEST_CORRELATION_ID
                                               newRefreshToken:@"refresh token from server"
                                                newAccessToken:@"access token from server"
                                                    newIDToken:[self adDefaultIDToken]];

    // explicitly set scope=open as the required field in request body
    [response setUrlFormEncodedBody:@{ MSID_OAUTH2_GRANT_TYPE : @"refresh_token",
                                       MSID_OAUTH2_REFRESH_TOKEN : @"refresh token from developer",
                                       MSID_OAUTH2_RESOURCE : TEST_RESOURCE,
                                       MSID_OAUTH2_CLIENT_ID : TEST_CLIENT_ID,
                                       MSID_OAUTH2_SCOPE : MSID_OAUTH2_SCOPE_OPENID_VALUE,
                                       MSID_OAUTH2_CLIENT_INFO: @"1"
                                       }];

    [ADTestURLSession addResponse:response];

    [context acquireTokenWithRefreshToken:@"refresh token from developer"
                                 resource:TEST_RESOURCE
                                 clientId:TEST_CLIENT_ID
                              redirectUri:TEST_REDIRECT_URL
                                   userId:@"mismatchuser@abc.com"
                          completionBlock:^(ADALAuthenticationResult *result)
     {
         // Should succeed
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         XCTAssertNil(result.error);
         XCTAssertNotNil(result.tokenCacheItem);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}

#if TARGET_OS_IPHONE
- (void)testAcquireToken_whenMrrtInCacheWrittenByMSAL_shouldBeAbleToFindAndUseIt
{
    // Write refresh token into keychain by using v2 token response
    ADALAuthenticationError *error = nil;
    ADALAuthenticationContext *context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithMrrtByMsal"];

    BOOL result = [_msalTokenCache saveTokensWithConfiguration:[self adCreateV2DefaultConfiguration]
                                                      response:[self adCreateV2TokenResponse]
                                                       context:nil
                                                         error:&error];
    XCTAssertNil(error);
    XCTAssertTrue(result);

    ADTestURLResponse *mrrtResponse =
    [self adResponseRefreshToken:TEST_REFRESH_TOKEN
                       authority:TEST_AUTHORITY
                        resource:TEST_RESOURCE
                        clientId:TEST_CLIENT_ID
                   correlationId:TEST_CORRELATION_ID
                 newRefreshToken:@"new family refresh token"
                  newAccessToken:@"new access token"
                      newIDToken:[self adDefaultIDToken]
                additionalFields:@{ ADAL_CLIENT_FAMILY_ID : @"1"}];
    [ADTestURLSession addResponse:mrrtResponse];

    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         XCTAssertNotNil(result.tokenCacheItem);
         XCTAssertEqualObjects(result.accessToken, @"new access token");
         XCTAssertEqualObjects(result.tokenCacheItem.refreshToken, @"new family refresh token");
         XCTAssertEqualObjects(result.tokenCacheItem.familyId, @"1");
         XCTAssertEqualObjects(result.authority, TEST_AUTHORITY);
         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}
#endif

- (void)testAcquireToken_whenPolicyProtectionRequiredErrorReturned_shouldNotRemoveTokenAndReturnUserId
{
    // Refresh tokens should only be deleted when the server returns a 'invalid_grant' error
    ADALAuthenticationError* error = nil;
    ADALAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    // Add an MRRT to the cache as well
    ADALTokenCacheItem* mrrtItem = [self adCreateMRRTCacheItem];
    [self.cacheDataSource addOrUpdateItem:mrrtItem correlationId:nil error:&error];
    XCTAssertNil(error);

    // Set up the mock connection to reject the MRRT with a policy protection required error
    MSIDTestURLResponse *response = [self adResponseBadRefreshToken:TEST_REFRESH_TOKEN
                                                          authority:TEST_AUTHORITY
                                                           resource:TEST_RESOURCE
                                                           clientId:TEST_CLIENT_ID
                                                         oauthError:@"unauthorized_client"
                                                      oauthSubError:@"protection_policy_required"
                                                      correlationId:TEST_CORRELATION_ID
                                                      requestParams:nil];
    [ADTestURLSession addResponse:response];

    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertNil(result.authority);
         XCTAssertEqual(result.error.code, AD_ERROR_SERVER_PROTECTION_POLICY_REQUIRED);
         XCTAssertEqualObjects(result.error.userInfo[ADUserIdKey], TEST_USER_ID);
         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];

    // The MRRT should still be in the cache
    NSArray* allItems = [self.cacheDataSource allItems:&error];
    XCTAssertNotNil(allItems);
    XCTAssertEqual(allItems.count, 1);
    XCTAssertEqualObjects(allItems[0], mrrtItem);
}

#if TARGET_OS_IPHONE
- (void)testAcquireToken_whenPolicyProtectionRequiredErrorReturned_andMRRTInDifferentCache_shouldNotRemoveTokenAndReturnUserId
{
    // Write MRRT refresh token into keychain by using v2 token response
    ADALAuthenticationError *error = nil;
    ADALAuthenticationContext *context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithMrrtByMsal"];

    BOOL result = [_msalTokenCache saveTokensWithConfiguration:[self adCreateV2DefaultConfiguration]
                                                      response:[self adCreateV2TokenResponse]
                                                       context:nil
                                                         error:&error];
    XCTAssertNil(error);
    XCTAssertTrue(result);

    // Set up the mock connection to reject the MRRT with a policy protection required error
    MSIDTestURLResponse *response = [self adResponseBadRefreshToken:TEST_REFRESH_TOKEN
                                                          authority:TEST_AUTHORITY
                                                           resource:TEST_RESOURCE
                                                           clientId:TEST_CLIENT_ID
                                                         oauthError:@"unauthorized_client"
                                                      oauthSubError:@"protection_policy_required"
                                                      correlationId:TEST_CORRELATION_ID
                                                      requestParams:nil];
    [ADTestURLSession addResponse:response];

    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertNil(result.authority);
         XCTAssertEqual(result.error.code, AD_ERROR_SERVER_PROTECTION_POLICY_REQUIRED);
         XCTAssertEqualObjects(result.error.userInfo[ADUserIdKey], TEST_USER_ID);
         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}
#endif

#pragma mark - Enrollment ID

- (void)testSilentForceRefresh_whenValidATAndMRRTInCache_shouldSkipCurrentATAndGetNewAT
{
    ADALAuthenticationError *error = nil;
    ADALAuthenticationContext *context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    // Add a valid access token to the cache
    ADALTokenCacheItem *item = [self adCreateATCacheItem];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);

    // Add an MRRT to the cache as well
    [self.cacheDataSource addOrUpdateItem:[self adCreateMRRTCacheItem] correlationId:nil error:&error];
    XCTAssertNil(error);

    [ADTestURLSession addResponse:[self adDefaultRefreshResponse:@"new refresh token" accessToken:@"new access token" newIDToken:[self adDefaultIDToken]]];

    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                               forceRefresh:YES
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         XCTAssertNotNil(result.tokenCacheItem);
         XCTAssertTrue([result.correlationId isKindOfClass:[NSUUID class]]);
         XCTAssertEqualObjects(result.accessToken, @"new access token");
         XCTAssertEqualObjects(result.authority, TEST_AUTHORITY);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];

    NSArray *allItems = [self.cacheDataSource allItems:&error];
    XCTAssertNil(error);
    XCTAssertNotNil(allItems);
    XCTAssertEqual(allItems.count, 2);

    ADALTokenCacheItem *mrrtItem = nil;
    ADALTokenCacheItem *atItem = nil;

    // Pull the MRRT and AT items out of the cache
    for (ADALTokenCacheItem  *item in allItems)
    {
        if (item.refreshToken)
        {
            mrrtItem = item;
        }
        else if (item.accessToken)
        {
            atItem = item;
        }
    }

    XCTAssertNotNil(mrrtItem);
    XCTAssertNotNil(atItem);

    XCTAssertNil(atItem.refreshToken);
    XCTAssertNil(mrrtItem.accessToken);

    // Make sure the tokens got updated
    XCTAssertEqualObjects(atItem.accessToken, @"new access token");
    XCTAssertEqualObjects(mrrtItem.refreshToken, @"new refresh token");
}

- (void)testSilentForceRefresh_whenValidATInCacheButNoMRRT_shouldReturnInteractionRequiredError
{
    ADALAuthenticationError *error = nil;
    ADALAuthenticationContext *context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    // Add a valid access token to the cache
    ADALTokenCacheItem *item = [self adCreateATCacheItem];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);

    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                               forceRefresh:YES
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertEqualObjects(result.error.domain, ADAuthenticationErrorDomain);
         XCTAssertEqual(result.error.code, AD_ERROR_SERVER_USER_INPUT_NEEDED);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testSilentForceRefresh_whenValidATAndSingleResourceRTInCache_shouldSkipCurrentATAndGetNewAT
{
    ADALAuthenticationError *error = nil;
    ADALAuthenticationContext *context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    // Add a valid access token and single resource RT to the cache
    ADALTokenCacheItem *item = [self adCreateCacheItem];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);

    [ADTestURLSession addResponse:[self adDefaultRefreshResponse:@"new refresh token" accessToken:@"new access token" newIDToken:[self adDefaultIDToken]]];

    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                               forceRefresh:YES
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         XCTAssertNotNil(result.tokenCacheItem);
         XCTAssertTrue([result.correlationId isKindOfClass:[NSUUID class]]);
         XCTAssertEqualObjects(result.accessToken, @"new access token");
         XCTAssertEqualObjects(result.tokenCacheItem.refreshToken, @"new refresh token");
         XCTAssertEqualObjects(result.authority, TEST_AUTHORITY);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testAcquireTokenInteractive_whenSystemErrorWhileAccessingTokenEndpoint_shouldSurfaceSystemError
{
    // Setup successful response at auth endpoint
    NSString *authCode = @"i_am_a_auth_code";
    
    NSURL *endURL = [NSURL URLWithString:[NSString stringWithFormat:@"%@?code=%@", TEST_REDIRECT_URL_STRING, authCode]];
    MSIDWebviewResponse *aadResponse = [[MSIDWebAADAuthResponse alloc] initWithURL:endURL context:nil error:nil];
    [ADTestWebAuthController setResponse:aadResponse];

    // Setup up system error response at token endpoint
    NSString* requestUrlString = [NSString stringWithFormat:@"%@/oauth2/token", TEST_AUTHORITY];
    NSMutableDictionary* headers = [[ADTestURLResponse defaultHeaders] mutableCopy];
    headers[@"client-request-id"] = [TEST_CORRELATION_ID UUIDString];

    NSError *systemError = [[NSError alloc] initWithDomain:NSURLErrorDomain code:NSURLErrorNotConnectedToInternet userInfo:nil];
    NSURL *requestUrl = [NSURL URLWithString:requestUrlString];
    ADTestURLResponse* response = [ADTestURLResponse request:requestUrl respondWithError:systemError];
    [response setRequestHeaders:headers];
    [response setUrlFormEncodedBody:@{ MSID_OAUTH2_GRANT_TYPE : MSID_OAUTH2_AUTHORIZATION_CODE,
                                       MSID_OAUTH2_CODE : authCode,
                                       MSID_OAUTH2_CLIENT_ID : TEST_CLIENT_ID,
                                       MSID_OAUTH2_REDIRECT_URI : TEST_REDIRECT_URL_STRING,
                                       MSID_OAUTH2_CLIENT_INFO: @"1"
                                       }];

    [ADTestURLSession addResponse:response];

    // Acquire token should surface the system error
    ADALAuthenticationContext *context = [self getTestAuthenticationContext];
    XCTAssertNotNil(context);
    context.correlationId = TEST_CORRELATION_ID;

    __block XCTestExpectation *expectation2 = [self expectationWithDescription:@"acquire token"];
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                       promptBehavior:AD_PROMPT_AUTO
                       userIdentifier:nil
                 extraQueryParameters:nil
                               claims:nil
                      completionBlock:^(ADALAuthenticationResult *result) {

                          XCTAssertNotNil(result);
                          XCTAssertEqual(result.status, AD_FAILED);
                          XCTAssertEqual(result.error.domain, NSURLErrorDomain);
                          XCTAssertEqual(result.error.code, NSURLErrorNotConnectedToInternet);
                          [expectation2 fulfill];
                      }];

    [self waitForExpectations:@[expectation2] timeout:1.0];
    
}

@end
