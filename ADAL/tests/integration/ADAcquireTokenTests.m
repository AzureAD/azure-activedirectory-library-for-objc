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
#import "ADAuthenticationContext+Internal.h"
#import "XCTestCase+TestHelperMethods.h"
#import <libkern/OSAtomic.h>
#import "ADWebRequest.h"
#import "ADTestURLSession.h"
#import "ADTestURLResponse.h"
#import "ADAuthenticationSettings.h"
#import "ADTokenCacheItem+Internal.h"
#import "ADTokenCacheDataSource.h"
#import "ADTelemetryTestDispatcher.h"
#import "ADUserIdentifier.h"
#import "ADTestAuthenticationViewController.h"
#import "ADAuthorityValidation.h"
#import "MSIDLegacyTokenCacheAccessor.h"
#import "MSIDLegacyTokenCacheAccessor.h"
#import "MSIDDefaultTokenCacheAccessor.h"
#import "ADAuthenticationContext+TestUtil.h"
#import "MSIDAADV2TokenResponse.h"
#import "MSIDAADV2Oauth2Factory.h"
#import "ADTokenCacheKey.h"
#import "MSIDBaseToken.h"
#import "MSIDAADV1Oauth2Factory.h"

#if TARGET_OS_IPHONE
#import "MSIDKeychainTokenCache+MSIDTestsUtil.h"
#import "MSIDKeychainTokenCache.h"
#import "ADLegacyKeychainTokenCache.h"
#else
#import "ADTokenCache+Internal.h"
#endif

const int sAsyncContextTimeout = 10;

@interface ADAuthenticationRequest (UnitTestExtension)

- (void)setAllowSilentRequests:(BOOL)allowSilent;

@end

@implementation ADAuthenticationRequest (UnitTestExtension)

- (void)setAllowSilentRequests:(BOOL)allowSilent
{
    _allowSilent = allowSilent;
}

@end

@interface ADAcquireTokenTests : ADTestCase

@property (nonatomic) MSIDLegacyTokenCacheAccessor *tokenCache;
@property (nonatomic) MSIDDefaultTokenCacheAccessor *msalTokenCache;
@property (nonatomic) id<ADTokenCacheDataSource> cacheDataSource;

@end

@implementation ADAcquireTokenTests

- (void)setUp
{
    [super setUp];
    
    [[ADAuthorityValidation sharedInstance] addInvalidAuthority:TEST_AUTHORITY];
    
#if TARGET_OS_IPHONE
    [MSIDKeychainTokenCache reset];
    
    self.cacheDataSource = ADLegacyKeychainTokenCache.defaultKeychainCache;

    MSIDDefaultTokenCacheAccessor *defaultTokenCacheAccessor = [[MSIDDefaultTokenCacheAccessor alloc] initWithDataSource:MSIDKeychainTokenCache.defaultKeychainCache otherCacheAccessors:nil factory:[MSIDAADV2Oauth2Factory new]];
    
    MSIDLegacyTokenCacheAccessor *legacyTokenCacheAccessor = [[MSIDLegacyTokenCacheAccessor alloc] initWithDataSource:MSIDKeychainTokenCache.defaultKeychainCache otherCacheAccessors:@[defaultTokenCacheAccessor] factory:[MSIDAADV1Oauth2Factory new]];
    
    self.tokenCache = legacyTokenCacheAccessor;
    self.msalTokenCache = defaultTokenCacheAccessor;
#else
    ADTokenCache *adTokenCache = [ADTokenCache new];
    self.cacheDataSource = adTokenCache;
    self.tokenCache = [[MSIDLegacyTokenCacheAccessor alloc] initWithDataSource:adTokenCache.macTokenCache otherCacheAccessors:nil factory:[MSIDAADV1Oauth2Factory new]];
#endif
}

- (void)tearDown
{
    [super tearDown];
    
    [ADTelemetry sharedInstance].piiEnabled = NO;
}

- (ADAuthenticationContext *)getTestAuthenticationContext
{
    ADAuthenticationContext* context =
        [[ADAuthenticationContext alloc] initWithAuthority:TEST_AUTHORITY
                                         validateAuthority:NO
                                                     error:nil];
    context.tokenCache = self.tokenCache;
    
    NSAssert(context, @"If this is failing for whatever reason you should probably fix it before trying to run tests.");
    
    [context setCorrelationId:TEST_CORRELATION_ID];
    
    return context;
}

- (void)testBadCompletionBlock
{
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    ADAssertThrowsArgument([context acquireTokenWithResource:TEST_RESOURCE clientId:TEST_CLIENT_ID redirectUri:TEST_REDIRECT_URL completionBlock:nil]);
}

- (void)testBadResource
{
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireToken without resource should return error."];
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    [context acquireTokenWithResource:nil
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                      completionBlock:^(ADAuthenticationResult *result)
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
                      completionBlock:^(ADAuthenticationResult *result)
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
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireToken without clientId should return error."];
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:nil
                          redirectUri:TEST_REDIRECT_URL
                      completionBlock:^(ADAuthenticationResult *result)
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
                      completionBlock:^(ADAuthenticationResult *result)
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
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"Expectation"];
    [context setCredentialsType:AD_CREDENTIALS_AUTO];
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:[NSURL URLWithString:@"urn:ietf:wg:oauth:2.0:oob"]
                      completionBlock:^(ADAuthenticationResult *result)
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
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenWithResource with bad extra query parameters."];
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                               userId:TEST_USER_ID
                 extraQueryParameters:@"login_hint=test1@馬克英家.com"
                      completionBlock:^(ADAuthenticationResult *result)
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
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenForAssertion with bad assertion."];
    [context acquireTokenForAssertion:nil
                        assertionType:AD_SAML1_1
                             resource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                               userId:TEST_USER_ID
                      completionBlock:^(ADAuthenticationResult *result)
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
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];

    // Add a token item to return in the cache
    ADTokenCacheItem* item = [self adCreateCacheItem];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);

    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenForAssertion with cached assertion."];
    [context acquireTokenForAssertion:@"some assertion"
                        assertionType:AD_SAML1_1
                             resource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                               userId:TEST_USER_ID
                      completionBlock:^(ADAuthenticationResult *result)
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
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    NSUUID* correlationId = TEST_CORRELATION_ID;

    NSString* broadRefreshToken = @"broad refresh token testAcquireTokenWithNoPrompt";
    NSString* anotherAccessToken = @"another access token testAcquireTokenWithNoPrompt";
    NSString* assertion = @"some assertion";
    NSString* base64Assertion = [[assertion dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0];

    NSMutableDictionary *headers = [[ADTestURLResponse defaultHeaders] mutableCopy];
    headers[MSID_OAUTH2_CORRELATION_ID_REQUEST_VALUE] = [correlationId UUIDString];

    ADTestURLResponse* response = [ADTestURLResponse requestURLString:@"https://login.windows.net/contoso.com/oauth2/token?x-client-Ver=" ADAL_VERSION_STRING
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
                      completionBlock:^(ADAuthenticationResult *result)
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

    ADAuthenticationError *error = nil;
    
    NSArray* allItems = [self.cacheDataSource allItems:&error];
    XCTAssertNil(error);
    XCTAssertNotNil(allItems);
    XCTAssertEqual(allItems.count, 2);
    
    ADTokenCacheItem* mrrtItem = nil;
    ADTokenCacheItem* atItem = nil;
    
    // Pull the MRRT and AT items out of the cache
    for (ADTokenCacheItem * item in allItems)
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
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];

    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenWithResource"];

    // Add a token item to return in the cache
    ADTokenCacheItem* item = [self adCreateCacheItem:@"eric@contoso.com"];
    BOOL result =  [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);
    XCTAssertTrue(result);

    // Because there's only one user in the cache calling acquire token with nil userId should
    // return this one item.
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                      completionBlock:^(ADAuthenticationResult *result)
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
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];

    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenWithResource"];

    // Add a token item to return in the cache
    ADTokenCacheItem* item = [self adCreateCacheItem:nil];
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
                            completionBlock:^(ADAuthenticationResult *result)
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

    ADTokenCacheItem *adfsToken = allItems[0];
    XCTAssertEqualObjects(adfsToken.refreshToken, TEST_REFRESH_TOKEN);
    XCTAssertEqualObjects(adfsToken.accessToken, @"new access token");
    XCTAssertNil(adfsToken.userInformation);
}

- (void)testFailsWithNilUserIdAndMultipleCachedUsers
{
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];

    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenWithResource"];

    // Add a token item to return in the cache
    [self.cacheDataSource addOrUpdateItem:[self adCreateCacheItem:@"eric@contoso.com"] correlationId:nil error:&error];
    [self.cacheDataSource addOrUpdateItem:[self adCreateCacheItem:@"stan@contoso.com"] correlationId:nil error:&error];

    // Because there's only one user in the cache calling acquire token with nil userId should
    // return this one item.
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                               userId:nil
                      completionBlock:^(ADAuthenticationResult *result)
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
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"Expectation"];

    // Add a token item to return in the cache
    ADTokenCacheItem* item = [self adCreateCacheItem:nil];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];

    // Because there's only one user in the cache calling acquire token should return that
    // item, even though there is no userId info in the item and we specified a user id.
    // This is done for ADFS users where a login hint might have been specified but we
    // can't verify it.
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                               userId:@"eric@contoso.com"
                      completionBlock:^(ADAuthenticationResult *result)
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
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    // With nothing cached the operation should fail telling the developer that
    // user input is required.
    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADAuthenticationResult *result)
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
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    // Add a token item to return in the cache
    ADTokenCacheItem* item = [self adCreateCacheItem];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];

    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADAuthenticationResult *result)
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

- (void)testSilentExpiredItemCached
{
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    // Add a expired access token with no refresh token to the cache
    ADTokenCacheItem* item = [self adCreateCacheItem];
    item.expiresOn = [NSDate date];
    item.refreshToken = nil;
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);

    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADAuthenticationResult *result)
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
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    // Add a expired access token with refresh token to the cache
    ADTokenCacheItem* item = [self adCreateCacheItem];
    item.expiresOn = [NSDate date];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);

    // Set the response to reject the refresh token
    [ADTestURLSession addResponse:[self adDefaultBadRefreshTokenResponse]];

    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADAuthenticationResult *result)
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
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    // Add a expired access token with refresh token to the cache
    ADTokenCacheItem* item = [self adCreateATCacheItem];
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
                            completionBlock:^(ADAuthenticationResult *result)
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
                            completionBlock:^(ADAuthenticationResult *result)
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
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    // Add a expired access token with refresh token to the cache
    ADTokenCacheItem* item = [self adCreateATCacheItem];
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
                            completionBlock:^(ADAuthenticationResult *result)
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

    ADTokenCacheItem* mrrtItem = nil;
    ADTokenCacheItem* atItem = nil;

    // Pull the MRRT and AT items out of the cache
    for (ADTokenCacheItem * item in allItems)
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
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    // Add a expired access token with refresh token to the cache
    ADTokenCacheItem* item = [self adCreateATCacheItem];
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
                            completionBlock:^(ADAuthenticationResult *result)
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

    ADTokenCacheItem* mrrtItem = nil;
    ADTokenCacheItem* atItem = nil;

    // Pull the MRRT and AT items out of the cache
    for (ADTokenCacheItem * item in allItems)
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
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenWithResource"];

    // Add a expired access token with refresh token to the cache
    ADTokenCacheItem* item = [self adCreateATCacheItem];
    item.expiresOn = [NSDate date];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);

    // Add an MRRT to the cache as well
    ADTokenCacheItem* mrrtItem = [self adCreateMRRTCacheItem];
    [self.cacheDataSource addOrUpdateItem:mrrtItem correlationId:nil error:&error];
    XCTAssertNil(error);

    // Set up the mock connection to simulate a no internet connection error
    ADTestURLResponse* response =
    [ADTestURLResponse request:[NSURL URLWithString:TEST_AUTHORITY "/oauth2/token?x-client-Ver=" ADAL_VERSION_STRING]
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
                      completionBlock:^(ADAuthenticationResult *result)
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

- (void)testMRRTUnauthorizedClient
{
    // Refresh tokens should only be deleted when the server returns a 'invalid_grant' error
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    // Add an MRRT to the cache as well
    ADTokenCacheItem* mrrtItem = [self adCreateMRRTCacheItem];
    [self.cacheDataSource addOrUpdateItem:mrrtItem correlationId:nil error:&error];
    XCTAssertNil(error);

    // Set up the mock connection to reject the MRRT with an error that should cause it to not remove the MRRT
    [ADTestURLSession addResponse:[self adDefaultBadRefreshTokenResponseError:@"unauthorized_client"]];

    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                            completionBlock:^(ADAuthenticationResult *result)
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
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenWithResource"];

    // Add a expired access token with refresh token to the cache
    ADTokenCacheItem* item = [self adCreateATCacheItem];
    item.expiresOn = [NSDate date];
    item.refreshToken = @"refresh token";
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);

    // Add an MRRT to the cache as well
    [self.cacheDataSource addOrUpdateItem:[self adCreateMRRTCacheItem] correlationId:nil error:&error];
    XCTAssertNil(error);

    ADTestURLResponse* response = [ADTestURLResponse requestURLString:@"https://login.windows.net/contoso.com/oauth2/token?x-client-Ver=" ADAL_VERSION_STRING
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
                      completionBlock:^(ADAuthenticationResult *result)
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
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    id<ADTokenCacheDataSource> cache = self.cacheDataSource;
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
                            completionBlock:^(ADAuthenticationResult *result)
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
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    id<ADTokenCacheDataSource> cache = self.cacheDataSource;
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
                            completionBlock:^(ADAuthenticationResult *result)
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
    ADTokenCacheKey* frtKey = [ADTokenCacheKey keyWithAuthority:TEST_AUTHORITY
                                                       resource:nil
                                                       clientId:@"foci-1"
                                                          error:&error];
    XCTAssertNotNil(frtKey);
    XCTAssertNil(error);

    ADTokenCacheItem* frtItem = [cache getItemWithKey:frtKey
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
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    id<ADTokenCacheDataSource> cache = self.cacheDataSource;
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
                            completionBlock:^(ADAuthenticationResult *result)
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

    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    id<ADTokenCacheDataSource> cache = self.cacheDataSource;
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
                            completionBlock:^(ADAuthenticationResult *result)
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
    ADTokenCacheKey* mrrtKey = [ADTokenCacheKey keyWithAuthority:TEST_AUTHORITY
                                                        resource:nil
                                                        clientId:TEST_CLIENT_ID
                                                           error:&error];
    XCTAssertNotNil(mrrtKey);
    XCTAssertNil(error);

    ADTokenCacheItem* mrrtItem = [cache getItemWithKey:mrrtKey userId:TEST_USER_ID correlationId:nil error:&error];
    XCTAssertNotNil(mrrtItem);
    XCTAssertNil(error);
    XCTAssertEqualObjects(mrrtItem.refreshToken, @"new family refresh token");
    XCTAssertEqualObjects(mrrtItem.familyId, @"1");

    ADTokenCacheKey* frtKey = [ADTokenCacheKey keyWithAuthority:TEST_AUTHORITY
                                                       resource:nil
                                                       clientId:@"foci-1"
                                                          error:&error];
    XCTAssertNotNil(frtKey);
    XCTAssertNil(error);

    ADTokenCacheItem* frtItem = [cache getItemWithKey:frtKey userId:TEST_USER_ID correlationId:nil error:&error];
    XCTAssertNotNil(frtItem);
    XCTAssertNil(error);
    XCTAssertEqualObjects(frtItem.refreshToken, @"new family refresh token");
}

- (void)testFRTFailFallbackToMRRT
{
    // In this case we have a MRRT marked with a family ID and a FRT that does not work, here we want
    // to make sure that we fallback onto the MRRT.
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    id<ADTokenCacheDataSource> cache = self.cacheDataSource;
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
                      correlationId:TEST_CORRELATION_ID];

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
                            completionBlock:^(ADAuthenticationResult *result)
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
    ADTokenCacheKey* mrrtKey = [ADTokenCacheKey keyWithAuthority:TEST_AUTHORITY
                                                        resource:nil
                                                        clientId:TEST_CLIENT_ID
                                                           error:&error];
    XCTAssertNotNil(mrrtKey);
    XCTAssertNil(error);

    ADTokenCacheItem* mrrtItem = [cache getItemWithKey:mrrtKey userId:TEST_USER_ID correlationId:nil error:&error];
    XCTAssertNotNil(mrrtItem);
    XCTAssertNil(error);
    XCTAssertEqualObjects(mrrtItem.refreshToken, @"new family refresh token");
    XCTAssertEqualObjects(mrrtItem.familyId, @"1");

    ADTokenCacheKey* frtKey = [ADTokenCacheKey keyWithAuthority:TEST_AUTHORITY
                                                       resource:nil
                                                       clientId:@"foci-1"
                                                          error:&error];
    XCTAssertNotNil(frtKey);
    XCTAssertNil(error);

    ADTokenCacheItem* frtItem = [cache getItemWithKey:frtKey userId:TEST_USER_ID correlationId:nil error:&error];
    XCTAssertNotNil(frtItem);
    XCTAssertNil(error);
    XCTAssertEqualObjects(frtItem.refreshToken, @"new family refresh token");
}

- (void)testFociMRRTWithNoFRT
{
    // This case is to make sure that if we have a MRRT marked with a family ID but no FRT in the
    // cache that we still use the MRRT
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];

    id<ADTokenCacheDataSource> cache = self.cacheDataSource;
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
                            completionBlock:^(ADAuthenticationResult *result)
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
    ADTokenCacheKey* mrrtKey = [ADTokenCacheKey keyWithAuthority:TEST_AUTHORITY
                                                        resource:nil
                                                        clientId:TEST_CLIENT_ID
                                                           error:&error];
    XCTAssertNotNil(mrrtKey);
    XCTAssertNil(error);

    ADTokenCacheItem* mrrtItem = [cache getItemWithKey:mrrtKey userId:TEST_USER_ID correlationId:nil error:&error];
    XCTAssertNotNil(mrrtItem);
    XCTAssertNil(error);
    XCTAssertEqualObjects(mrrtItem.refreshToken, @"new family refresh token");
    XCTAssertEqualObjects(mrrtItem.familyId, @"1");

    ADTokenCacheKey* frtKey = [ADTokenCacheKey keyWithAuthority:TEST_AUTHORITY
                                                       resource:nil
                                                       clientId:@"foci-1"
                                                          error:&error];
    XCTAssertNotNil(frtKey);
    XCTAssertNil(error);

    ADTokenCacheItem* frtItem = [cache getItemWithKey:frtKey userId:TEST_USER_ID correlationId:nil error:&error];
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
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    id<ADTokenCacheDataSource> cache = self.cacheDataSource;
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
                      completionBlock:^(ADAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         XCTAssertNil(result.error);
         XCTAssertEqualObjects(result.authority, TEST_AUTHORITY);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];

    // retrieve the AT from cache
    ADTokenCacheKey* atKey = [ADTokenCacheKey keyWithAuthority:TEST_AUTHORITY
                                                        resource:TEST_RESOURCE
                                                        clientId:TEST_CLIENT_ID
                                                           error:&error];
    XCTAssertNotNil(atKey);
    XCTAssertNil(error);

    ADTokenCacheItem* atItem = [cache getItemWithKey:atKey userId:TEST_USER_ID correlationId:nil error:&error];
    XCTAssertNotNil(atItem);
    XCTAssertNil(error);

    // Make sure ext_expires_on is in the AT and set with proper value
    NSDate* extExpires = [atItem.additionalServer valueForKey:@"ext_expires_on"];
    NSDate* expectedExpiresTime = [NSDate dateWithTimeIntervalSinceNow:3600];
    XCTAssertNotNil(extExpires);
    XCTAssertTrue([expectedExpiresTime timeIntervalSinceDate:extExpires]<10); // 10 secs as tolerance

    // Purposely expire the AT
    atItem.expiresOn = [NSDate date];
    [cache addOrUpdateItem:atItem correlationId:nil error:&error];
    XCTAssertNil(error);

    // Test resiliency when response code 500 ... 599 happens
    ADTestURLResponse* response = [ADTestURLResponse requestURLString:[NSString stringWithFormat:@"%@/oauth2/token?x-client-Ver=" ADAL_VERSION_STRING, TEST_AUTHORITY]
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
                      completionBlock:^(ADAuthenticationResult *result)
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
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    id<ADTokenCacheDataSource> cache = self.cacheDataSource;
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
                      completionBlock:^(ADAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         XCTAssertNil(result.error);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];

    // Purposely expire the AT
    ADTokenCacheKey* atKey = [ADTokenCacheKey keyWithAuthority:TEST_AUTHORITY
                                                      resource:TEST_RESOURCE
                                                      clientId:TEST_CLIENT_ID
                                                         error:&error];
    XCTAssertNotNil(atKey);
    XCTAssertNil(error);

    ADTokenCacheItem* atItem = [cache getItemWithKey:atKey userId:TEST_USER_ID correlationId:nil error:&error];
    XCTAssertNotNil(atItem);
    XCTAssertNil(error);

    atItem.expiresOn = [NSDate date];
    [cache addOrUpdateItem:atItem correlationId:nil error:&error];
    XCTAssertNil(error);

    // Delete the MRRT
    ADTokenCacheKey* rtKey = [ADTokenCacheKey keyWithAuthority:TEST_AUTHORITY
                                                      resource:nil
                                                      clientId:TEST_CLIENT_ID
                                                         error:&error];
    XCTAssertNotNil(rtKey);
    XCTAssertNil(error);

    ADTokenCacheItem* rtItem = [cache getItemWithKey:rtKey userId:TEST_USER_ID correlationId:nil error:&error];
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
                            completionBlock:^(ADAuthenticationResult *result)
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

- (void)testAllowSilentRequestParameters
{
    XCTestExpectation* expectation = [self expectationWithDescription:@"requestToken"];
    ADAuthenticationContext *context = [self getTestAuthenticationContext];
    ADRequestParameters *params = [[ADRequestParameters alloc] initWithAuthority:context.authority
                                                                        resource:TEST_RESOURCE
                                                                        clientId:TEST_CLIENT_ID
                                                                     redirectUri:TEST_REDIRECT_URL.absoluteString
                                                                      identifier:[ADUserIdentifier identifierWithId:TEST_USER_ID]
                                                                extendedLifetime:NO
                                                                   correlationId:nil
                                                              telemetryRequestId:nil
                                                                    logComponent:nil];
    
    ADAuthenticationRequest *req = [ADAuthenticationRequest requestWithContext:context
                                                                 requestParams:params
                                                                    tokenCache:self.tokenCache
                                                                         error:nil];
    [req setSilent:YES];
    [req setAllowSilentRequests:YES];

    // Following we add a mock response and specify the request url we expect (it must include login_hint)
    ADTestURLResponse* response = [ADTestURLResponse new];
    [response setRequestURL:[NSURL URLWithString:@"https://login.windows.net/contoso.com/oauth2/authorize?client_id=c3c7f5e5-7153-44d4-90e6-329686d48d76&prompt=none&resource=resource&redirect_uri=urn%3Aietf%3Awg%3Aoauth%3A2.0%3Aoob&nux=1&response_type=code&login_hint=eric_cartman%40contoso.com&x-client-Ver=" ADAL_VERSION_STRING]];

    NSMutableDictionary *headers = [[ADTestURLResponse defaultHeaders] mutableCopy];

    // TODO: It doesn't make sense to be sending this content type, seeing how there is no body, but we're sending it anyways
    headers[@"Content-Type"] = @"application/x-www-form-urlencoded";
    [response setRequestHeaders:headers];
    [response setResponseURL:@"https://idontmatter.com" code:401 headerFields:@{}];
    [ADTestURLSession addResponse:response];

    // We send the actual silent network request
    [req requestToken:^(ADAuthenticationResult *result)
     {
         // if request url is not expected,
         // our network mock will fail the unit test and it won't hit here
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_SERVER_USER_INPUT_NEEDED);
         XCTAssertNil(result.authority);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];
}

- (void)testAllowSilentRequestParameters_whenAuthCodeReturned_shouldSucceed
{
    XCTestExpectation* expectation = [self expectationWithDescription:@"requestToken"];
    ADAuthenticationContext *context = [self getTestAuthenticationContext];
    ADRequestParameters *params = [[ADRequestParameters alloc] initWithAuthority:context.authority
                                                                        resource:TEST_RESOURCE
                                                                        clientId:TEST_CLIENT_ID
                                                                     redirectUri:TEST_REDIRECT_URL.absoluteString
                                                                      identifier:[ADUserIdentifier identifierWithId:TEST_USER_ID]
                                                                extendedLifetime:NO
                                                                   correlationId:TEST_CORRELATION_ID
                                                              telemetryRequestId:nil
                                                                    logComponent:nil];
    
    ADAuthenticationRequest *req = [ADAuthenticationRequest requestWithContext:context
                                                                 requestParams:params
                                                                    tokenCache:self.tokenCache
                                                                         error:nil];
    [req setSilent:YES];
    [req setAllowSilentRequests:YES];

    // Add a mock response returning auth code for the allowSilent request
    ADTestURLResponse* response = [ADTestURLResponse new];
    [response setRequestURL:[NSURL URLWithString:@"https://login.windows.net/contoso.com/oauth2/authorize?prompt=none&response_type=code&login_hint=eric_cartman%40contoso.com&resource=resource&nux=1&redirect_uri=urn%3Aietf%3Awg%3Aoauth%3A2.0%3Aoob&client_id=c3c7f5e5-7153-44d4-90e6-329686d48d76&x-client-Ver=" ADAL_VERSION_STRING]];
    NSMutableDictionary *headers = [[ADTestURLResponse defaultHeaders] mutableCopy];
    headers[@"Content-Type"] = @"application/x-www-form-urlencoded";
    [response setRequestHeaders:headers];
    [response setResponseURL:[NSString stringWithFormat:@"%@?code=fake_auth_code", TEST_REDIRECT_URL_STRING]
                        code:401
                headerFields:@{}];
    [ADTestURLSession addResponse:response];

    // Add a mock response returning tokens
    [ADTestURLSession addResponse:[self adResponseAuthCode:@"fake_auth_code"
                                                 authority:context.authority
                                             correlationId:TEST_CORRELATION_ID]];

    // We send the actual silent network request
    [req requestToken:^(ADAuthenticationResult *result)
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

- (void)testSkipCacheRequestParameters_whenSkipCacheIsNotSet_shouldNotSkipCache
{
    ADAuthenticationError* error = nil;
    ADAuthenticationContext *context = [self getTestAuthenticationContext];
    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireToken"];
    ADRequestParameters *params = [[ADRequestParameters alloc] initWithAuthority:context.authority
                                                                        resource:TEST_RESOURCE
                                                                        clientId:TEST_CLIENT_ID
                                                                     redirectUri:TEST_REDIRECT_URL.absoluteString
                                                                      identifier:[ADUserIdentifier identifierWithId:TEST_USER_ID]
                                                                extendedLifetime:NO
                                                                   correlationId:nil
                                                              telemetryRequestId:nil
                                                                    logComponent:nil];

    // Add a token item to return in the cache
    ADTokenCacheItem* item = [self adCreateCacheItem];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];

    // No skipCache is set, cached item should be found
    
    ADAuthenticationRequest *req = [ADAuthenticationRequest requestWithContext:context
                                                                 requestParams:params
                                                                    tokenCache:self.tokenCache
                                                                         error:nil];
    [req acquireToken:@"123"
      completionBlock:^(ADAuthenticationResult *result)
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
    ADAuthenticationError* error = nil;
    ADAuthenticationContext *context = [self getTestAuthenticationContext];
    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireToken"];
    ADRequestParameters *params = [[ADRequestParameters alloc] initWithAuthority:context.authority
                                                                        resource:TEST_RESOURCE
                                                                        clientId:TEST_CLIENT_ID
                                                                     redirectUri:TEST_REDIRECT_URL.absoluteString
                                                                      identifier:[ADUserIdentifier identifierWithId:TEST_USER_ID]
                                                                extendedLifetime:NO
                                                                   correlationId:nil
                                                              telemetryRequestId:nil
                                                                    logComponent:nil];

    // Add a token item to return in the cache
    ADTokenCacheItem* item = [self adCreateCacheItem];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];

    // skipCache is set, cache should be skipped and webview controller should be hit
    ADAuthenticationRequest *req = [ADAuthenticationRequest requestWithContext:context
                                                                 requestParams:params
                                                                    tokenCache:self.tokenCache
                                                                         error:nil];
    [req setSkipCache:YES];

    // Add a specific error as mock response to webview controller
    [ADTestAuthenticationViewController addDelegateCallWebAuthDidFailWithError:[NSError errorWithDomain:ADAuthenticationErrorDomain code:AD_ERROR_UI_NO_MAIN_VIEW_CONTROLLER userInfo:nil]];

    [req acquireToken:@"123"
      completionBlock:^(ADAuthenticationResult *result)
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

- (void)testAcquireToken_whenClaimsIsPassedViaOverloadedAcquireToken_shouldSkipCache
{
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithResource"];

    // Add a token item to cache
    ADTokenCacheItem* item = [self adCreateCacheItem];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];

    // Add a specific error as mock response to webview controller
    [ADTestAuthenticationViewController addDelegateCallWebAuthDidFailWithError:[NSError errorWithDomain:ADAuthenticationErrorDomain code:AD_ERROR_UI_NO_MAIN_VIEW_CONTROLLER userInfo:nil]];

    // "claims" is passed in, cache should be skipped and webview controller should be hit
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                       promptBehavior:AD_PROMPT_AUTO
                       userIdentifier:[ADUserIdentifier identifierWithId:TEST_USER_ID]
                 extraQueryParameters:nil
                               claims:@"%7B%22access_token%22%3A%7B%22polids%22%3A%7B%22essential%22%3Atrue%2C%22values%22%3A%5B%225ce770ea-8690-4747-aa73-c5b3cd509cd4%22%5D%7D%7D%7D"
                      completionBlock:^(ADAuthenticationResult *result)
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

- (void)testAcquireToken_whenClaimsIsNotProperlyEncoded_shouldReturnError
{
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithResource"];

    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                       promptBehavior:AD_PROMPT_AUTO
                       userIdentifier:[ADUserIdentifier identifierWithId:TEST_USER_ID]
                 extraQueryParameters:nil
                               claims:@"{\"access_token\":{\"polids\":{\"essential\":true,\"values\":[\"5ce770ea-8690-4747-aa73-c5b3cd509cd4\"]}}}"
                      completionBlock:^(ADAuthenticationResult *result)
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

- (void)testAcquireToken_whenClaimsIsNil_shouldNotSkipCache
{
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithResource"];

    // Add a token item to return in the cache
    ADTokenCacheItem* item = [self adCreateCacheItem];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];

    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                       promptBehavior:AD_PROMPT_AUTO
                       userIdentifier:[ADUserIdentifier identifierWithId:TEST_USER_ID]
                 extraQueryParameters:nil
                               claims:nil
                      completionBlock:^(ADAuthenticationResult *result)
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
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithResource"];

    // Add a token item to return in the cache
    ADTokenCacheItem* item = [self adCreateCacheItem];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];

    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                       promptBehavior:AD_PROMPT_AUTO
                       userIdentifier:[ADUserIdentifier identifierWithId:TEST_USER_ID]
                 extraQueryParameters:nil
                               claims:@""
                      completionBlock:^(ADAuthenticationResult *result)
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
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithResource"];

    // Add a specific error as mock response to webview controller
    [ADTestAuthenticationViewController addDelegateCallWebAuthDidFailWithError:[NSError errorWithDomain:ADAuthenticationErrorDomain code:AD_ERROR_UI_NO_MAIN_VIEW_CONTROLLER userInfo:nil]];

    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                       promptBehavior:AD_PROMPT_AUTO
                       userIdentifier:[ADUserIdentifier identifierWithId:TEST_USER_ID]
                 extraQueryParameters:@"claims=%7B%22access_token%22%3A%7B%22polids%22%3A%7B%22essential%22%3Atrue%2C%22values%22%3A%5B%225ce770ea-8690-4747-aa73-c5b3cd509cd4%22%5D%7D%7D%7D"
                               claims:@"%7B%22access_token%22%3A%7B%22polids%22%3A%7B%22essential%22%3Atrue%2C%22values%22%3A%5B%225ce770ea-8690-4747-aa73-c5b3cd509cd4%22%5D%7D%7D%7D"
                      completionBlock:^(ADAuthenticationResult *result)
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
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenWithResource"];

    // Add an MRRT to the cache
    ADTokenCacheItem* mrrtItem = [self adCreateMRRTCacheItem];
    [self.cacheDataSource addOrUpdateItem:mrrtItem correlationId:nil error:&error];
    XCTAssertNil(error);

    // Set up the mock connection to simulate a 429 throttled error
    NSString* requestURLString = TEST_AUTHORITY "/oauth2/token?x-client-Ver=" ADAL_VERSION_STRING;

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
                      completionBlock:^(ADAuthenticationResult *result)
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
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithRefreshToken"];

    [context acquireTokenWithRefreshToken:nil
                                 resource:TEST_RESOURCE
                                 clientId:TEST_CLIENT_ID
                              redirectUri:TEST_REDIRECT_URL
                      completionBlock:^(ADAuthenticationResult *result)
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
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
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
                          completionBlock:^(ADAuthenticationResult *result)
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
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
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
                          completionBlock:^(ADAuthenticationResult *result)
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
                            completionBlock:^(ADAuthenticationResult *result)
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
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
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
                                                    correlationId:TEST_CORRELATION_ID];
    
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
                          completionBlock:^(ADAuthenticationResult *result)
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
    ADTokenCacheItem *rtInCache = [self.cacheDataSource getItemWithKey:[self.adCreateMRRTCacheItem extractKey:nil]  userId:TEST_USER_ID correlationId:TEST_CORRELATION_ID error:nil];
    XCTAssertNotNil(rtInCache);
}

- (void)testAcquireTokenWithRefreshTokenAndUserId_whenRefreshTokenIsNotPassedIn_shouldReturnError
{
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithRefreshToken"];
    
    [context acquireTokenWithRefreshToken:nil
                                 resource:TEST_RESOURCE
                                 clientId:TEST_CLIENT_ID
                              redirectUri:TEST_REDIRECT_URL
                                   userId:TEST_USER_ID
                          completionBlock:^(ADAuthenticationResult *result)
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
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
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
                          completionBlock:^(ADAuthenticationResult *result)
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
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
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
                          completionBlock:^(ADAuthenticationResult *result)
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
                            completionBlock:^(ADAuthenticationResult *result)
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
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
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
                                                    correlationId:TEST_CORRELATION_ID];
    
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
                          completionBlock:^(ADAuthenticationResult *result)
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
    ADTokenCacheItem *rtInCache = [self.cacheDataSource getItemWithKey:[self.adCreateMRRTCacheItem extractKey:nil]  userId:TEST_USER_ID correlationId:TEST_CORRELATION_ID error:nil];
    XCTAssertNotNil(rtInCache);
}

- (void)testAcquireTokenWithRefreshTokenAndUserId_whenRefreshTokenAndUserIdMismatch_shouldReturnError
{
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
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
                          completionBlock:^(ADAuthenticationResult *result)
     {
         //error is returned because user id provided does not match the refresh token
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertEqual(result.error.domain, ADAuthenticationErrorDomain);
         XCTAssertEqual(result.error.code, AD_ERROR_SERVER_WRONG_USER);
         
         [expectation fulfill];
     }];
    
    [self waitForExpectations:@[expectation] timeout:1];
}

#if TARGET_OS_IPHONE
- (void)testAcquireToken_whenMrrtInCacheWrittenByMSAL_shouldBeAbleToFindAndUseIt
{
    // Write refresh token into keychain by using v2 token response
    ADAuthenticationError *error = nil;
    ADAuthenticationContext *context = [self getTestAuthenticationContext];
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
                            completionBlock:^(ADAuthenticationResult *result)
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

@end
