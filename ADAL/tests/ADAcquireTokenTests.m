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
#import "ADTestURLConnection.h"
#import "ADOAuth2Constants.h"
#import "ADAuthenticationSettings.h"
#import "ADKeychainTokenCache+Internal.h"
#import "ADTestURLConnection.h"
#import "ADTokenCache+Internal.h"
#import "ADTokenCacheItem+Internal.h"

const int sAsyncContextTimeout = 10;

@interface ADAcquireTokenTests : XCTestCase
{
@private
    dispatch_semaphore_t _dsem;
}
@end

#define TEST_SIGNAL dispatch_semaphore_signal(_dsem)
#define TEST_WAIT dispatch_semaphore_wait(_dsem, DISPATCH_TIME_FOREVER)

@implementation ADAcquireTokenTests

- (void)setUp
{
    [super setUp];
    [self adTestBegin:ADAL_LOG_LEVEL_INFO];
    _dsem = dispatch_semaphore_create(0);
}

- (void)tearDown
{
#if !__has_feature(objc_arc)
    dispatch_release(_dsem);
#endif
    _dsem = nil;
    
    XCTAssertTrue([ADTestURLConnection noResponsesLeft]);
    [ADTestURLConnection clearResponses];
    [self adTestEnd];
    [super tearDown];
}

- (ADAuthenticationContext *)getTestAuthenticationContext
{
    ADAuthenticationContext* context =
        [[ADAuthenticationContext alloc] initWithAuthority:TEST_AUTHORITY
                                         validateAuthority:NO
                                                     error:nil];
    
    NSAssert(context, @"If this is failing for whatever reason you should probably fix it before trying to run tests.");
    ADTokenCache *tokenCache = [ADTokenCache new];
    SAFE_ARC_AUTORELEASE(tokenCache);
    [context setTokenCacheStore:tokenCache];
    [context setCorrelationId:TEST_CORRELATION_ID];
    
    SAFE_ARC_AUTORELEASE(context);
    
    return context;
}

- (void)testBadCompletionBlock
{
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    ADAssertThrowsArgument([context acquireTokenWithResource:TEST_RESOURCE clientId:TEST_CLIENT_ID redirectUri:TEST_REDIRECT_URL completionBlock:nil]);
}

- (void)testBadResource
{
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
        
        TEST_SIGNAL;
    }];
    
    TEST_WAIT;
    
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
         
         TEST_SIGNAL;
     }];
    
    TEST_WAIT;
}

- (void)testBadClientId
{
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:nil
                          redirectUri:TEST_REDIRECT_URL
                      completionBlock:^(ADAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);
         ADTAssertContains(result.error.errorDetails, @"clientId");
         
         TEST_SIGNAL;
     }];
    
    TEST_WAIT;
    
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:@"    "
                          redirectUri:TEST_REDIRECT_URL
                      completionBlock:^(ADAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);
         ADTAssertContains(result.error.errorDetails, @"clientId");
         
         TEST_SIGNAL;
     }];
    
    TEST_WAIT;
}

- (void)testAssertionBadAssertion
{
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    
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
         ADTAssertContains(result.error.errorDetails, @"samlAssertion");
         
         TEST_SIGNAL;
     }];
    
    TEST_WAIT;
}

- (void)testAssertionCached
{
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    
    // Add a token item to return in the cache
    ADTokenCacheItem* item = [self adCreateCacheItem];
    [[context tokenCacheStore] addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);
    
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
        
        TEST_SIGNAL;
    }];
    
    TEST_WAIT;
}

- (void)testAssertionNetwork
{
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    NSUUID* correlationId = TEST_CORRELATION_ID;
    
    NSString* broadRefreshToken = @"broad refresh token testAcquireTokenWithNoPrompt";
    NSString* anotherAccessToken = @"another access token testAcquireTokenWithNoPrompt";
    NSString* assertion = @"some assertion";
    NSString* base64Assertion = [[assertion dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0];
    
    ADTestURLResponse* response = [ADTestURLResponse requestURLString:@"https://login.windows.net/contoso.com/oauth2/token?x-client-Ver=" ADAL_VERSION_STRING
                                                       requestHeaders:@{ OAUTH2_CORRELATION_ID_REQUEST_VALUE : [correlationId UUIDString] }
                                                    requestParamsBody:@{ OAUTH2_GRANT_TYPE : OAUTH2_SAML11_BEARER_VALUE,
                                                                         OAUTH2_SCOPE : OAUTH2_SCOPE_OPENID_VALUE,
                                                                         OAUTH2_RESOURCE : TEST_RESOURCE,
                                                                         OAUTH2_CLIENT_ID : TEST_CLIENT_ID,
                                                                         OAUTH2_ASSERTION : base64Assertion }
                                                    responseURLString:@"https://contoso.com"
                                                         responseCode:400
                                                     httpHeaderFields:@{ OAUTH2_CORRELATION_ID_REQUEST_VALUE : [correlationId UUIDString] }
                                                     dictionaryAsJSON:@{ OAUTH2_ACCESS_TOKEN : anotherAccessToken,
                                                                         OAUTH2_REFRESH_TOKEN : broadRefreshToken,
                                                                         OAUTH2_TOKEN_TYPE : TEST_ACCESS_TOKEN_TYPE,
                                                                         OAUTH2_RESOURCE : TEST_RESOURCE,
                                                                         OAUTH2_GRANT_TYPE : OAUTH2_SAML11_BEARER_VALUE,
                                                                         OAUTH2_SCOPE : OAUTH2_SCOPE_OPENID_VALUE
                                                                         }];
    [ADTestURLConnection addResponse:response];
    
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
         
         TEST_SIGNAL;
     }];
    
    TEST_WAIT;
    
    XCTAssertTrue([ADTestURLConnection noResponsesLeft]);
}


- (void)testCachedWithNilUserId
{
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    
    // Add a token item to return in the cache
    ADTokenCacheItem* item = [self adCreateCacheItem:@"eric@contoso.com"];
    [[context tokenCacheStore] addOrUpdateItem:item correlationId:nil error:&error];
    
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
        
        TEST_SIGNAL;
    }];
    
    TEST_WAIT;
}

- (void)testFailsWithNilUserIdAndMultipleCachedUsers
{
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    
    // Add a token item to return in the cache
    [[context tokenCacheStore] addOrUpdateItem:[self adCreateCacheItem:@"eric@contoso.com"] correlationId:nil error:&error];
    [[context tokenCacheStore] addOrUpdateItem:[self adCreateCacheItem:@"stan@contoso.com"] correlationId:nil error:&error];
    
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
         
         TEST_SIGNAL;
     }];
    
    TEST_WAIT;
}

- (void)testCachedWithNoIdtoken
{
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    
    // Add a token item to return in the cache
    ADTokenCacheItem* item = [self adCreateCacheItem:nil];
    [[context tokenCacheStore] addOrUpdateItem:item correlationId:nil error:&error];
    
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
         
         TEST_SIGNAL;
     }];
    
    TEST_WAIT;
}

- (void)testSilentNothingCached
{
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    
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
         
         TEST_SIGNAL;
    }];
    
    TEST_WAIT;
}

- (void)testSilentItemCached
{
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    
    // Add a token item to return in the cache
    ADTokenCacheItem* item = [self adCreateCacheItem];
    [[context tokenCacheStore] addOrUpdateItem:item correlationId:nil error:&error];
    
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
         
         TEST_SIGNAL;
     }];
    
    TEST_WAIT;
}

- (void)testSilentExpiredItemCached
{
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    
    // Add a expired access token with no refresh token to the cache
    ADTokenCacheItem* item = [self adCreateCacheItem];
    item.expiresOn = [NSDate date];
    item.refreshToken = nil;
    [[context tokenCacheStore] addOrUpdateItem:item correlationId:nil error:&error];
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
         
         TEST_SIGNAL;
     }];
    
    TEST_WAIT;
    
    // Also verify the expired item has been removed from the cache
    NSArray* allItems = [context.tokenCacheStore allItems:&error];
    XCTAssertNil(error);
    XCTAssertEqual(allItems.count, 0);
}

- (void)testSilentBadRefreshToken
{
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    
    // Add a expired access token with refresh token to the cache
    ADTokenCacheItem* item = [self adCreateCacheItem];
    item.expiresOn = [NSDate date];
    [[context tokenCacheStore] addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);
    
    // Set the response to reject the refresh token
    [ADTestURLConnection addResponse:[self adDefaultBadRefreshTokenResponse]];
    
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
         
         TEST_SIGNAL;
     }];
    
    TEST_WAIT;
    
    XCTAssertTrue([ADTestURLConnection noResponsesLeft]);
    
    // Also verify the expired item has been removed from the cache
    NSArray* allItems = [context.tokenCacheStore allItems:&error];
    XCTAssertNil(error);
    XCTAssertEqual(allItems.count, 0);
}

- (void)testSilentExpiredATBadMRRT
{
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    
    // Add a expired access token with refresh token to the cache
    ADTokenCacheItem* item = [self adCreateATCacheItem];
    item.expiresOn = [NSDate date];
    [[context tokenCacheStore] addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);
    
    // Add an MRRT to the cache as well
    [[context tokenCacheStore] addOrUpdateItem:[self adCreateMRRTCacheItem] correlationId:nil error:&error];
    XCTAssertNil(error);
    
    // Set the response to reject the refresh token
    [ADTestURLConnection addResponse:[self adDefaultBadRefreshTokenResponse]];
    
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
         
         TEST_SIGNAL;
     }];
    
    TEST_WAIT;
    
    NSArray* tombstones = [[context tokenCacheStore] allTombstones:&error];
    XCTAssertEqual(tombstones.count, 1);
    
    // Verify that both the expired AT and the rejected MRRT are removed from the cache
    NSArray* allItems = [context.tokenCacheStore allItems:&error];
    XCTAssertNil(error);
    
    XCTAssertTrue([ADTestURLConnection noResponsesLeft]);
    XCTAssertEqual(allItems.count, 0);
    
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
         
         TEST_SIGNAL;
     }];
    
    TEST_WAIT;
}

- (void)testSilentExpiredATRefreshMRRTNetwork
{
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    
    // Add a expired access token with refresh token to the cache
    ADTokenCacheItem* item = [self adCreateATCacheItem];
    item.expiresOn = [NSDate date];
    [[context tokenCacheStore] addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);
    
    // Add an MRRT to the cache as well
    [[context tokenCacheStore] addOrUpdateItem:[self adCreateMRRTCacheItem] correlationId:nil error:&error];
    XCTAssertNil(error);
    
    [ADTestURLConnection addResponse:[self adDefaultRefreshResponse:@"new refresh token" accessToken:@"new access token"]];
    
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
         
         TEST_SIGNAL;
     }];
    
    TEST_WAIT;
    
    NSArray* allItems = [[context tokenCacheStore] allItems:&error];
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
    
    // Add a expired access token with refresh token to the cache
    ADTokenCacheItem* item = [self adCreateATCacheItem];
    item.expiresOn = [NSDate date];
    [[context tokenCacheStore] addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);
    
    // Add an MRRT to the cache as well
    ADTokenCacheItem* mrrtItem = [self adCreateMRRTCacheItem];
    [[context tokenCacheStore] addOrUpdateItem:mrrtItem correlationId:nil error:&error];
    XCTAssertNil(error);
    
    // Set up the mock connection to simulate a no internet connection error
    ADTestURLResponse* response =
    [ADTestURLResponse request:[NSURL URLWithString:TEST_AUTHORITY "/oauth2/token?x-client-Ver=" ADAL_VERSION_STRING]
              respondWithError:[NSError errorWithDomain:NSURLErrorDomain
                                                   code:NSURLErrorNotConnectedToInternet
                                               userInfo:nil]];
    [ADTestURLConnection addResponse:response];
    
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
        
        TEST_SIGNAL;
    }];
    
    TEST_WAIT;
    
    // The expired AT should be removed from the cache but the MRRT should still be there.
    NSArray* allItems = [[context tokenCacheStore] allItems:&error];
    XCTAssertNotNil(allItems);
    XCTAssertEqual(allItems.count, 1);
    XCTAssertEqualObjects(allItems[0], mrrtItem);
}

- (void)testRequestRetryOnUnusualHttpResponse
{
    //Create a normal authority (not a test one):
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    
    // Add a expired access token with refresh token to the cache
    ADTokenCacheItem* item = [self adCreateATCacheItem];
    item.expiresOn = [NSDate date];
    item.refreshToken = @"refresh token";
    [[context tokenCacheStore] addOrUpdateItem:item correlationId:nil error:&error];
    XCTAssertNil(error);
    
    // Add an MRRT to the cache as well
    [[context tokenCacheStore] addOrUpdateItem:[self adCreateMRRTCacheItem] correlationId:nil error:&error];
    XCTAssertNil(error);
    
    ADTestURLResponse* response = [ADTestURLResponse requestURLString:@"https://login.windows.net/contoso.com/oauth2/token?x-client-Ver=" ADAL_VERSION_STRING
                                                    responseURLString:@"https://contoso.com"
                                                         responseCode:500
                                                     httpHeaderFields:@{ } // maybe shoehorn correlation ID here
                                                     dictionaryAsJSON:@{ OAUTH2_ERROR : @"server_error",
                                                                         OAUTH2_ERROR_DESCRIPTION : @"AADSTS90036: Non-retryable error has occurred." }];
    
    //It should hit network twice for trying and retrying the refresh token because it is an server error
    //Then hit network twice again for broad refresh token for the same reason
    //So totally 4 responses are added
    //If there is an infinite retry, exception will be thrown becasuse there is not enough responses
    [ADTestURLConnection addResponse:response];
    [ADTestURLConnection addResponse:response];
    
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                               userId:TEST_USER_ID
                      completionBlock:^(ADAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         
         TEST_SIGNAL;
     }];
    
    TEST_WAIT;
    
    NSArray* allItems = [[context tokenCacheStore] allItems:&error];
    XCTAssertNotNil(allItems);
    XCTAssertEqual(allItems.count, 2);
}

// Make sure that if we get a token response from the server that includes a family ID we cache it properly
- (void)testAcquireRefreshFamilyTokenNetwork
{
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    
    XCTAssertTrue([[context tokenCacheStore] addOrUpdateItem:[self adCreateMRRTCacheItem] correlationId:nil error:&error]);
    XCTAssertNil(error);
    
    ADTestURLResponse* response = [self adResponseRefreshToken:TEST_REFRESH_TOKEN
                                                     authority:TEST_AUTHORITY
                                                      resource:TEST_RESOURCE
                                                      clientId:TEST_CLIENT_ID
                                                 correlationId:TEST_CORRELATION_ID
                                               newRefreshToken:TEST_REFRESH_TOKEN
                                                newAccessToken:TEST_ACCESS_TOKEN
                                              additionalFields:@{ ADAL_CLIENT_FAMILY_ID : @"familyId"}];
    
    [ADTestURLConnection addResponse:response];
    
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
        XCTAssertEqualObjects(result.tokenCacheItem.familyId, @"familyId");
        TEST_SIGNAL;
    }];

    TEST_WAIT;
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

@end
