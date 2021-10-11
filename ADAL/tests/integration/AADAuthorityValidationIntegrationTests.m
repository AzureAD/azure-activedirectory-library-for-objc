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


#import "ADALAuthenticationContext+Internal.h"
#import "ADALAuthenticationResult.h"
#import "MSIDAadAuthorityCache.h"
#import "ADALAuthorityValidation.h"
#import "ADALAuthorityValidationRequest.h"
#import "ADALDrsDiscoveryRequest.h"
#import "ADALTokenCacheTestUtil.h"
#import "ADTestURLSession.h"
#import "ADTestURLResponse.h"
#import "ADALTokenCache+Internal.h"
#import "ADALTokenCacheItem+Internal.h"
#import "ADALTokenCacheKey.h"
#import "ADALUserIdentifier.h"
#import "ADALWebFingerRequest.h"
#import "MSIDLegacyTokenCacheAccessor.h"
#import "ADALKeychainTokenCache+Internal.h"
#import "MSIDLegacyTokenCacheAccessor.h"
#import "MSIDKeychainTokenCache.h"
#import "ADALAuthenticationContext+TestUtil.h"
#import "MSIDAADV1Oauth2Factory.h"
#import "MSIDAadAuthorityCacheRecord.h"

#import "XCTestCase+TestHelperMethods.h"
#import <XCTest/XCTest.h>

#import "ADTestWebAuthController.h"
#import "MSIDWebOAuth2Response.h"

@interface AADALAuthorityValidationTests : ADTestCase

@property (nonatomic) MSIDLegacyTokenCacheAccessor *tokenCache;
@property (nonatomic) ADALTokenCache *ADALTokenCache;

@end

@implementation AADALAuthorityValidationTests

- (void)setUp
{
    [super setUp];

    self.ADALTokenCache = [ADALTokenCache new];
    self.tokenCache = [[MSIDLegacyTokenCacheAccessor alloc] initWithDataSource:self.ADALTokenCache.macTokenCache otherCacheAccessors:nil factory:[MSIDAADV1Oauth2Factory new]];
}

- (void)tearDown
{
    [super tearDown];
}

#pragma mark - Tests

//Does not call the server, just passes invalid authority
- (void)testCheckAuthority_whenSchemeIsHttp_shouldFailWithError
{
    NSString *authority = @"http://invalidscheme.com";
    ADALRequestParameters* requestParams = [ADALRequestParameters new];
    requestParams.correlationId = [NSUUID UUID];
    
    ADALAuthorityValidation* authorityValidation = [[ADALAuthorityValidation alloc] init];
    
    [requestParams setAuthority:authority];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"Validate invalid authority."];
    [authorityValidation checkAuthority:requestParams
                      validateAuthority:YES
                        completionBlock:^(BOOL validated, ADALAuthenticationError *error)
     {
         XCTAssertFalse(validated, @"\"%@\" should come back invalid.", authority);
         XCTAssertNotNil(error);
         
         [expectation fulfill];
     }];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
}

- (void)testCheckAuthority_whenAuthorityUrlIsInvalid_shouldFailWithError
{
    NSString *authority = @"https://Invalid URL 2305 8 -0238460-820-386";
    ADALRequestParameters* requestParams = [ADALRequestParameters new];
    requestParams.correlationId = [NSUUID UUID];

    ADALAuthorityValidation* authorityValidation = [[ADALAuthorityValidation alloc] init];

    [requestParams setAuthority:authority];

    XCTestExpectation* expectation = [self expectationWithDescription:@"Validate invalid authority."];
    [authorityValidation checkAuthority:requestParams
                      validateAuthority:YES
                        completionBlock:^(BOOL validated, ADALAuthenticationError *error)
     {
         XCTAssertFalse(validated, @"\"%@\" should come back invalid.", authority);
         XCTAssertNotNil(error);

         [expectation fulfill];
     }];

    [self waitForExpectationsWithTimeout:1 handler:nil];
}

// Tests a normal authority
- (void)testCheckAuthority_whenAuthorityValid_shouldPass
{
    NSString* authority = @"https://login.windows-ppe.net/common";

    ADALAuthorityValidation* authorityValidation = [[ADALAuthorityValidation alloc] init];
    ADALRequestParameters* requestParams = [ADALRequestParameters new];
    requestParams.authority = authority;
    requestParams.correlationId = [NSUUID UUID];

    [ADTestURLSession addResponse:[ADTestAuthorityValidationResponse validAuthority:authority]];

    XCTestExpectation* expectation = [self expectationWithDescription:@"Validate valid authority."];
    [authorityValidation checkAuthority:requestParams
                      validateAuthority:YES
                        completionBlock:^(BOOL validated, ADALAuthenticationError * error)
     {
         XCTAssertTrue(validated);
         XCTAssertNil(error);

         [expectation fulfill];
     }];

    [self waitForExpectationsWithTimeout:1 handler:nil];

    MSIDAadAuthorityCacheRecord *record = [authorityValidation.aadCache objectForKey:[NSURL URLWithString:authority].msidHostWithPortIfNecessary];
    XCTAssertTrue(record.validated);
}

//Ensures that an invalid authority is not approved
- (void)testCheckAuthority_whenAuthorityInvalid_shouldReturnError
{
    NSString* authority = @"https://myfakeauthority.microsoft.com/contoso.com";

    ADALAuthorityValidation* authorityValidation = [[ADALAuthorityValidation alloc] init];
    ADALRequestParameters* requestParams = [ADALRequestParameters new];
    requestParams.authority = authority;
    requestParams.correlationId = [NSUUID UUID];

    [ADTestURLSession addResponse:[ADTestAuthorityValidationResponse invalidAuthority:authority validationEnabled:YES]];

    XCTestExpectation* expectation = [self expectationWithDescription:@"Validate invalid authority."];
    [authorityValidation checkAuthority:requestParams
                      validateAuthority:YES
                        completionBlock:^(BOOL validated, ADALAuthenticationError * error)
     {
         XCTAssertFalse(validated);
         XCTAssertNotNil(error);
         XCTAssertEqual(error.code, AD_ERROR_DEVELOPER_AUTHORITY_VALIDATION);

         [expectation fulfill];
     }];

    [self waitForExpectationsWithTimeout:1 handler:nil];

    MSIDAadAuthorityCacheRecord *record = [authorityValidation.aadCache objectForKey:[NSURL URLWithString:authority].msidHostWithPortIfNecessary];
    XCTAssertNotNil(record);
    XCTAssertFalse(record.validated);
    XCTAssertNotNil(record.error);
}

//Ensures there is no error with an invalid authority if validateAuthority is turned off.
- (void)testCheckAuthority_whenAuthorityInvalidAndNoValidation_shouldReturnNoError
{
    NSString* authority = @"https://myfakeauthority.microsoft.com/contoso.com";

    ADALAuthorityValidation* authorityValidation = [[ADALAuthorityValidation alloc] init];
    ADALRequestParameters* requestParams = [ADALRequestParameters new];
    requestParams.authority = authority;
    requestParams.correlationId = [NSUUID UUID];

    [ADTestURLSession addResponse:[ADTestAuthorityValidationResponse invalidAuthority:authority validationEnabled:NO]];

    XCTestExpectation* expectation = [self expectationWithDescription:@"Validate invalid authority."];
    [authorityValidation checkAuthority:requestParams
                      validateAuthority:NO
                        completionBlock:^(BOOL validated, ADALAuthenticationError * error)
     {
         XCTAssertFalse(validated);
         XCTAssertNil(error);

         [expectation fulfill];
     }];

    [self waitForExpectationsWithTimeout:1 handler:nil];

    MSIDAadAuthorityCacheRecord *record = [authorityValidation.aadCache objectForKey:[NSURL URLWithString:authority].msidHostWithPortIfNecessary];
    XCTAssertNotNil(record);
    XCTAssertFalse(record.validated);
    XCTAssertNotNil(record.error);
}

- (void)testAcquireToken_whenAuthorityInvalid_shouldReturnError
{
    ADALAuthenticationError* error = nil;

    NSString* authority = @"https://myfakeauthority.microsoft.com/contoso.com";

    ADALAuthenticationContext* context = [[ADALAuthenticationContext alloc] initWithAuthority:authority
                                                                        validateAuthority:YES
                                                                                    error:&error];

    XCTAssertNotNil(context);
    XCTAssertNil(error);

    [ADTestURLSession addResponse:[ADTestAuthorityValidationResponse invalidAuthority:authority validationEnabled:YES]];

    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithResource: with invalid authority."];
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                               userId:TEST_USER_ID
                      completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_DEVELOPER_AUTHORITY_VALIDATION);

         [expectation fulfill];
     }];

    [self waitForExpectationsWithTimeout:1 handler:nil];

    MSIDAadAuthorityCacheRecord *record = [[ADALAuthorityValidation sharedInstance].aadCache objectForKey:[NSURL URLWithString:authority].msidHostWithPortIfNecessary];
    XCTAssertNotNil(record);
    XCTAssertFalse(record.validated);
}

- (void)testAcquireToken_whenAuthorityInvalidWithAuthorityValidationOff_shouldGetMetadataSucceed
{
    ADALAuthenticationError *error = nil;
    NSString *authority = @"https://myfakeauthority.microsoft.com/contoso.com";
    NSString *updatedAT = @"updated-access-token";
    NSString *updatedRT = @"updated-refresh-token";
    
    ADALTokenCacheItem *mrrt = [self adCreateMRRTCacheItem];
    mrrt.authority = authority;
    
    [self.ADALTokenCache addOrUpdateItem:mrrt correlationId:nil error:nil];

    ADALAuthenticationContext *context = [[ADALAuthenticationContext alloc] initWithAuthority:authority
                                                                        validateAuthority:NO
                                                                                    error:&error];
    context.tokenCache = self.tokenCache;
    [context setCorrelationId:TEST_CORRELATION_ID];

    XCTAssertNotNil(context);
    XCTAssertNil(error);

    // Network Responses
    ADTestURLResponse *tokenResponse =
    [self adResponseRefreshToken:TEST_REFRESH_TOKEN
                       authority:authority
                        resource:TEST_RESOURCE
                        clientId:TEST_CLIENT_ID
                   correlationId:TEST_CORRELATION_ID
                 newRefreshToken:updatedRT
                  newAccessToken:updatedAT
                      newIDToken:[self adDefaultIDToken]
                additionalFields:@{ @"foci" : @"1" }];
    [ADTestURLSession addResponses:@[[ADTestAuthorityValidationResponse invalidAuthority:authority validationEnabled:NO],
                                     tokenResponse]];

    __block XCTestExpectation *expectation = [self expectationWithDescription:@"acquire token"];
    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);

         // Make sure the cache authority didn't change
         XCTAssertEqualObjects(result.tokenCacheItem.authority, authority);
         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1.0];

    // Make sure the cache properly updated the AT, MRRT and FRT...
    XCTAssertEqualObjects([self.ADALTokenCache getMRRT:authority], updatedRT);
    XCTAssertEqualObjects([self.ADALTokenCache getFRT:authority], updatedRT);
    XCTAssertEqualObjects([self.ADALTokenCache getAT:authority], updatedAT);

    MSIDAadAuthorityCacheRecord *record = [[ADALAuthorityValidation sharedInstance].aadCache objectForKey:[NSURL URLWithString:authority].msidHostWithPortIfNecessary];
    XCTAssertNotNil(record);
    XCTAssertFalse(record.validated);
}

- (void)testCheckAuthority_whenHostUnreachable_shouldFail
{
    NSString* authority = @"https://login.windows.net/contoso.com";

    ADALAuthorityValidation* authorityValidation = [[ADALAuthorityValidation alloc] init];
    ADALRequestParameters* requestParams = [ADALRequestParameters new];
    requestParams.authority = authority;
    requestParams.correlationId = [NSUUID UUID];

    NSURL* requestURL = [ADALAuthorityValidationRequest urlForAuthorityValidation:authority trustedHost:@"login.windows.net"];
    NSString* requestURLString = requestURL.absoluteString;
    
    requestURL = [NSURL URLWithString:requestURLString];

    NSError* responseError = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorCannotFindHost userInfo:nil];

    ADTestURLResponse *response = [ADTestURLResponse request:requestURL
                                            respondWithError:responseError];
    [response setRequestHeaders:[ADTestURLResponse defaultHeaders]];

    [ADTestURLSession addResponse:response];

    XCTestExpectation* expectation = [self expectationWithDescription:@"validateAuthority when server is unreachable."];

    [authorityValidation checkAuthority:requestParams
                      validateAuthority:YES
                        completionBlock:^(BOOL validated, ADALAuthenticationError *error)
     {
         XCTAssertFalse(validated);
         XCTAssertNotNil(error);

         [expectation fulfill];
     }];

    [self waitForExpectationsWithTimeout:1 handler:nil];

    // Failing to connect should not create a validation record
    MSIDAadAuthorityCacheRecord *record = [[ADALAuthorityValidation sharedInstance].aadCache objectForKey:[NSURL URLWithString:authority].msidHostWithPortIfNecessary];
    XCTAssertNil(record);
}

- (void)testAcquireTokenSilent_whenMultipleCalls_shouldOnlyValidateOnce
{
    NSString *authority = @"https://login.contoso.com/common";
    NSString *resource1 = @"resource1";
    NSString *resource2 = @"resource2";
    NSUUID *correlationId1 = [NSUUID new];
    NSUUID *correlationId2 = [NSUUID new];

    // Network Setup
    NSArray *metadata = @[ @{ @"preferred_network" : @"login.contoso.com",
                              @"preferred_cache" : @"login.contoso.com",
                              @"aliases" : @[ @"sts.contoso.com", @"login.contoso.com"] } ];
    dispatch_semaphore_t validationSem = dispatch_semaphore_create(0);
    ADTestURLResponse *validationResponse = [ADTestAuthorityValidationResponse validAuthority:authority withMetadata:metadata];
    [validationResponse setWaitSemaphore:validationSem];
    ADTestURLResponse *tokenResponse1 = [self adResponseRefreshToken:TEST_REFRESH_TOKEN
                                                           authority:authority
                                                            resource:resource1
                                                            clientId:TEST_CLIENT_ID
                                                       correlationId:correlationId1
                                                     newRefreshToken:TEST_REFRESH_TOKEN
                                                      newAccessToken:@"new-at-1"
                                                          newIDToken:[self adDefaultIDToken]];
    ADTestURLResponse *tokenResponse2 = [self adResponseRefreshToken:TEST_REFRESH_TOKEN
                                                           authority:authority
                                                            resource:resource2
                                                            clientId:TEST_CLIENT_ID
                                                       correlationId:correlationId2
                                                     newRefreshToken:TEST_REFRESH_TOKEN
                                                      newAccessToken:@"new-at-2"
                                                          newIDToken:[self adDefaultIDToken]];
    [ADTestURLSession addResponse:validationResponse];
    [ADTestURLSession addResponse:tokenResponse1];
    [ADTestURLSession addResponse:tokenResponse2];

    // This semaphore makes sure that both acquireToken calls have been made before we hit the
    // validationSem to allow the authority validation response to go through.
    dispatch_semaphore_t asyncSem = dispatch_semaphore_create(0);

    dispatch_queue_t concurrentQueue = dispatch_queue_create("test queue", DISPATCH_QUEUE_CONCURRENT);
    __block XCTestExpectation *expectation1 = [self expectationWithDescription:@"acquire thread 1"];
    dispatch_async(concurrentQueue, ^{
        ADALAuthenticationContext *context = [ADALAuthenticationContext authenticationContextWithAuthority:authority error:nil];
        context.tokenCache = self.tokenCache;
        XCTAssertNotNil(context);
        
        ADALTokenCacheItem *mrrt = [self adCreateMRRTCacheItem];
        mrrt.authority = authority;
        [self.ADALTokenCache addOrUpdateItem:mrrt correlationId:nil error:nil];
        
        [context setCorrelationId:correlationId1];

        [context acquireTokenSilentWithResource:resource1
                                       clientId:TEST_CLIENT_ID
                                    redirectUri:TEST_REDIRECT_URL
                                         userId:TEST_USER_ID
                                completionBlock:^(ADALAuthenticationResult *result)
         {
             XCTAssertNotNil(result);
             XCTAssertEqual(result.status, AD_SUCCEEDED);
             [expectation1 fulfill];
         }];

        // The first semaphore makes sure both acquireToken calls have been made
        dispatch_semaphore_wait(asyncSem, DISPATCH_TIME_FOREVER);

        // The second semaphore releases the validation response, so we can be sure this test is
        // properly validating that the correct behavior happens when there are two different acquire
        // token calls waiting on AAD validaiton cache
        dispatch_semaphore_signal(validationSem);
    });

    __block XCTestExpectation *expectation2 = [self expectationWithDescription:@"acquire thread 2"];
    dispatch_async(concurrentQueue, ^{
        ADALAuthenticationContext *context = [ADALAuthenticationContext authenticationContextWithAuthority:authority error:nil];
        context.tokenCache = self.tokenCache;
        ADALTokenCacheItem *mrrt = [self adCreateMRRTCacheItem];
        mrrt.authority = authority;
        [self.ADALTokenCache addOrUpdateItem:mrrt correlationId:nil error:nil];
        [context setCorrelationId:correlationId2];
        XCTAssertNotNil(context);
        [context acquireTokenSilentWithResource:resource2
                                       clientId:TEST_CLIENT_ID
                                    redirectUri:TEST_REDIRECT_URL
                                         userId:TEST_USER_ID
                                completionBlock:^(ADALAuthenticationResult *result)
         {
             XCTAssertNotNil(result);
             XCTAssertEqual(result.status, AD_SUCCEEDED);
             [expectation2 fulfill];
         }];

        dispatch_semaphore_signal(asyncSem);
    });

    [self waitForExpectations:@[expectation1, expectation2] timeout:5.0];
}

- (void)testAcquireTokenSilent_whenDifferentPreferredNetwork_shouldUsePreferred
{
    NSString *authority = @"https://login.contoso.com/common";
    NSString *preferredAuthority = @"https://login.contoso.net/common";

    // Network Setup
    NSArray *metadata = @[ @{ @"preferred_network" : @"login.contoso.net",
                              @"preferred_cache" : @"login.contoso.com",
                              @"aliases" : @[ @"login.contoso.net", @"login.contoso.com"] } ];
    ADTestURLResponse *validationResponse = [ADTestAuthorityValidationResponse validAuthority:authority withMetadata:metadata];
    ADTestURLResponse *tokenResponse = [self adResponseRefreshToken:TEST_REFRESH_TOKEN
                                                          authority:preferredAuthority
                                                           resource:TEST_RESOURCE
                                                           clientId:TEST_CLIENT_ID
                                                      correlationId:TEST_CORRELATION_ID
                                                    newRefreshToken:@"new-rt-1"
                                                     newAccessToken:@"new-at-1"
                                                         newIDToken:[self adDefaultIDToken]];

    [ADTestURLSession addResponses:@[validationResponse, tokenResponse]];

    ADALAuthenticationContext *context = [ADALAuthenticationContext authenticationContextWithAuthority:authority error:nil];
    context.tokenCache = self.tokenCache;
    ADALTokenCacheItem *mrrt = [self adCreateMRRTCacheItem];
    mrrt.authority = authority;
    [self.ADALTokenCache addOrUpdateItem:mrrt correlationId:nil error:nil];
    
    [context setCorrelationId:TEST_CORRELATION_ID];
    XCTAssertNotNil(context);

    __block XCTestExpectation *expectation = [self expectationWithDescription:@"acquire token"];
    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);

         // Make sure the cache authority didn't change
         XCTAssertEqualObjects(result.tokenCacheItem.authority, authority);
         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1.0];
}

- (void)testAcquireTokenSilent_whenDifferentPreferredNetworkValidateOff_shouldUsePreferred
{
    NSString *authority = @"https://login.contoso.com/common";
    NSString *preferredAuthority = @"https://login.contoso.net/common";

    // Network Setup
    NSArray *metadata = @[ @{ @"preferred_network" : @"login.contoso.net",
                              @"preferred_cache" : @"login.contoso.com",
                              @"aliases" : @[ @"login.contoso.net", @"login.contoso.com"] } ];
    ADTestURLResponse *validationResponse = [ADTestAuthorityValidationResponse validAuthority:authority trustedHost:@"login.contoso.com" withMetadata:metadata];
    ADTestURLResponse *tokenResponse = [self adResponseRefreshToken:TEST_REFRESH_TOKEN
                                                          authority:preferredAuthority
                                                           resource:TEST_RESOURCE
                                                           clientId:TEST_CLIENT_ID
                                                      correlationId:TEST_CORRELATION_ID
                                                    newRefreshToken:@"new-rt-1"
                                                     newAccessToken:@"new-at-1"
                                                         newIDToken:[self adDefaultIDToken]];

    [ADTestURLSession addResponses:@[validationResponse, tokenResponse]];

    ADALAuthenticationContext *context = [ADALAuthenticationContext authenticationContextWithAuthority:authority validateAuthority:NO error:nil];
    context.tokenCache = self.tokenCache;
    ADALTokenCacheItem *mrrt = [self adCreateMRRTCacheItem];
    mrrt.authority = authority;
    [self.ADALTokenCache addOrUpdateItem:mrrt correlationId:nil error:nil];
    [context setCorrelationId:TEST_CORRELATION_ID];
    XCTAssertNotNil(context);

    __block XCTestExpectation *expectation = [self expectationWithDescription:@"acquire token"];
    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);

         // Make sure the cache authority didn't change
         XCTAssertEqualObjects(result.tokenCacheItem.authority, authority);
         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1.0];
}

- (void)testAcquireTokenInteractive_whenDifferentPreferredNetwork_shouldUsePreferred
{
    NSString *authority = @"https://login.contoso.com/common";
    NSString *preferredAuthority = @"https://login.contoso.net/common";
    NSString *authCode = @"i_am_a_auth_code";

    // Network Setup
    NSArray *metadata = @[ @{ @"preferred_network" : @"login.contoso.net",
                              @"preferred_cache" : @"login.contoso.com",
                              @"aliases" : @[ @"login.contoso.net", @"login.contoso.com"] } ];
    ADTestURLResponse *validationResponse = [ADTestAuthorityValidationResponse validAuthority:authority withMetadata:metadata];
    ADTestURLResponse *authCodeResponse = [self adResponseAuthCode:authCode authority:preferredAuthority correlationId:TEST_CORRELATION_ID];
    [ADTestURLSession addResponses:@[validationResponse, authCodeResponse]];

    ADALAuthenticationContext *context = [ADALAuthenticationContext authenticationContextWithAuthority:authority error:nil];
    context.tokenCache = self.tokenCache;
    XCTAssertNotNil(context);
    [context setCorrelationId:TEST_CORRELATION_ID];

    NSURL *endURL = [NSURL URLWithString:[NSString stringWithFormat:@"%@?code=%@", TEST_REDIRECT_URL_STRING, authCode]];
    MSIDWebOAuth2Response *response = [[MSIDWebOAuth2Response alloc] initWithURL:endURL
                                                                         context:nil
                                                                           error:nil];
    [ADTestWebAuthController setResponse:response];

    __block XCTestExpectation *expectation = [self expectationWithDescription:@"acquire token"];
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                      completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1.0];
}

static NSString *s_doNotUseRT = @"do not use me";

static ADTestURLResponse *
CreateAuthorityValidationResponse(NSString *contextAuthority,
                                  NSString *networkAuthority,
                                  NSString *cacheAuthority)
{
    NSURL *contextUrl = [NSURL URLWithString:contextAuthority];
    NSURL *networkUrl = networkAuthority ? [NSURL URLWithString:networkAuthority] : contextUrl;
    NSURL *cacheUrl = cacheAuthority ? [NSURL URLWithString:cacheAuthority] : contextUrl;

    NSMutableSet *aliases = [NSMutableSet new];
    [aliases addObject:[contextUrl msidHostWithPortIfNecessary]];
    [aliases addObject:[networkUrl msidHostWithPortIfNecessary]];
    [aliases addObject:[cacheUrl msidHostWithPortIfNecessary]];

    NSArray *metadata = @[ @{ @"preferred_network" : [networkUrl msidHostWithPortIfNecessary],
                              @"preferred_cache" : [cacheUrl msidHostWithPortIfNecessary],
                              @"aliases" : [aliases allObjects] } ];
    return [ADTestAuthorityValidationResponse validAuthority:[networkUrl absoluteString] withMetadata:metadata];
}

static ADALAuthenticationContext *CreateAuthContext(NSString *authority)
{
    ADALAuthenticationContext *context = [ADALAuthenticationContext authenticationContextWithAuthority:authority error:nil];
    [context setCorrelationId:TEST_CORRELATION_ID];

    return context;
}

- (void)testAcquireTokenSilent_whenNoPreferredCache_shouldWriteToPreferred
{
    NSString *authority = @"https://login.contoso.com/common";
    NSString *preferredAuthority = @"https://login.contoso.net/common";
    NSString *updatedAT = @"updated-access-token";
    NSString *updatedRT = @"updated-refresh-token";

    // Network Responses
    ADTestURLResponse *tokenResponse =
    [self adResponseRefreshToken:TEST_REFRESH_TOKEN
                       authority:authority
                        resource:TEST_RESOURCE
                        clientId:TEST_CLIENT_ID
                   correlationId:TEST_CORRELATION_ID
                 newRefreshToken:updatedRT
                  newAccessToken:updatedAT
                      newIDToken:[self adDefaultIDToken]
                additionalFields:@{ @"foci" : @"1" }];
    ADTestURLResponse *validationResponse = CreateAuthorityValidationResponse(authority, nil, preferredAuthority);
    [ADTestURLSession addResponses:@[validationResponse, tokenResponse]];

    ADALTokenCacheItem *mrrt = [self adCreateMRRTCacheItem];
    mrrt.authority = authority;
    [self.ADALTokenCache addOrUpdateItem:mrrt correlationId:nil error:nil];
    
    ADALAuthenticationContext *context = CreateAuthContext(authority);
    context.tokenCache = self.tokenCache;

    __block XCTestExpectation *expectation = [self expectationWithDescription:@"acquire token"];
    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);

         // Make sure the cache authority didn't change
         XCTAssertEqualObjects(result.tokenCacheItem.authority, authority);
         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1.0];

    // Make sure the cache properly updated the AT, MRRT and FRT...
    XCTAssertEqualObjects([self.ADALTokenCache getMRRT:preferredAuthority], updatedRT);
    XCTAssertEqualObjects([self.ADALTokenCache getFRT:preferredAuthority], updatedRT);
    XCTAssertEqualObjects([self.ADALTokenCache getAT:preferredAuthority], updatedAT);

    // And that the non-preferred location did not get touched
    XCTAssertEqualObjects([self.ADALTokenCache getMRRT:authority], TEST_REFRESH_TOKEN);
    XCTAssertNil([self.ADALTokenCache getFRT:authority]);
    XCTAssertNil([self.ADALTokenCache getAT:authority]);
}

- (void)testAcquireTokenSilent_whenDifferentPreferredCache_shouldUsePreferred
{
    NSString *authority = @"https://login.contoso.com/common";
    NSString *preferredAuthority = @"https://login.contoso.net/common";
    NSString *updatedAT = @"updated-access-token";
    NSString *updatedRT = @"updated-refresh-token";

    // Network Responses
    ADTestURLResponse *tokenResponse =
    [self adResponseRefreshToken:TEST_REFRESH_TOKEN
                       authority:authority
                        resource:TEST_RESOURCE
                        clientId:TEST_CLIENT_ID
                   correlationId:TEST_CORRELATION_ID
                 newRefreshToken:updatedRT
                  newAccessToken:updatedAT
                      newIDToken:[self adDefaultIDToken]
                additionalFields:@{ @"foci" : @"1" }];
    ADTestURLResponse *validationResponse = CreateAuthorityValidationResponse(authority, nil, preferredAuthority);
    [ADTestURLSession addResponses:@[validationResponse, tokenResponse]];

    ADALTokenCacheItem *mrrt = [self adCreateMRRTCacheItem];
    mrrt.authority = preferredAuthority;
    [self.ADALTokenCache addOrUpdateItem:mrrt correlationId:nil error:nil];
    
    // Also add a MRRT in the non-preferred location to ignore
    ADALTokenCacheItem *otherMrrt = [self adCreateMRRTCacheItem];
    otherMrrt.authority = authority;
    otherMrrt.refreshToken = s_doNotUseRT;
    [self.ADALTokenCache addOrUpdateItem:otherMrrt correlationId:nil error:nil];
    
    ADALAuthenticationContext *context = CreateAuthContext(authority);
    context.tokenCache = self.tokenCache;

    __block XCTestExpectation *expectation = [self expectationWithDescription:@"acquire token"];
    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);

         // Make sure the cache authority didn't change
         XCTAssertEqualObjects(result.tokenCacheItem.authority, authority);
         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1];

    // Make sure the cache properly updated the AT, MRRT and FRT...
    XCTAssertEqualObjects([self.ADALTokenCache getMRRT:preferredAuthority], updatedRT);
    XCTAssertEqualObjects([self.ADALTokenCache getFRT:preferredAuthority], updatedRT);
    XCTAssertEqualObjects([self.ADALTokenCache getAT:preferredAuthority], updatedAT);

    // And that the non-preferred location did not get touched
    XCTAssertEqualObjects([self.ADALTokenCache getMRRT:authority], s_doNotUseRT);
    XCTAssertNil([self.ADALTokenCache getFRT:authority]);
    XCTAssertNil([self.ADALTokenCache getAT:authority]);
}

- (void)testAcquireTokenSilent_whenDifferentPreferredCacheAndTokenFails_shouldRemoveCorrectToken
{
    NSString *authority = @"https://login.contoso.com/common";
    NSString *preferredAuthority = @"https://login.contoso.net/common";

    // Network Responses
    ADTestURLResponse *tokenResponse =
    [self adResponseBadRefreshToken:TEST_REFRESH_TOKEN
                          authority:authority
                           resource:TEST_RESOURCE
                           clientId:TEST_CLIENT_ID
     // invalid_grant should result in ADAL tombstoning the token
                         oauthError:@"invalid_grant"
                      oauthSubError:nil
                      correlationId:TEST_CORRELATION_ID
                      requestParams:nil];
    
    ADTestURLResponse *validationResponse = CreateAuthorityValidationResponse(authority, nil, preferredAuthority);
    [ADTestURLSession addResponses:@[validationResponse, tokenResponse]];

    ADALTokenCacheItem *mrrt = [self adCreateMRRTCacheItem];
    mrrt.authority = preferredAuthority;
    [self.ADALTokenCache addOrUpdateItem:mrrt correlationId:nil error:nil];
    
    // Also add a MRRT in the non-preferred location to ignore
    ADALTokenCacheItem *otherMrrt = [self adCreateMRRTCacheItem];
    otherMrrt.authority = authority;
    otherMrrt.refreshToken = s_doNotUseRT;
    BOOL result = [self.ADALTokenCache addOrUpdateItem:otherMrrt correlationId:nil error:nil];
    XCTAssertTrue(result);
    
    ADALAuthenticationContext *context = CreateAuthContext(authority);
    context.tokenCache = self.tokenCache;

    __block XCTestExpectation *expectation = [self expectationWithDescription:@"acquire token"];
    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADALAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1.0];

    // Make sure the cache properly updated the AT, MRRT and FRT...
    ADALTokenCacheKey *mrrtKey = [ADALTokenCacheKey keyWithAuthority:preferredAuthority resource:nil clientId:TEST_CLIENT_ID error:nil];
    ADALTokenCacheItem *preferredMRRT = [self.ADALTokenCache getItemsWithKey:mrrtKey userId:TEST_USER_ID correlationId:nil error:nil].firstObject;
    XCTAssertNil(preferredMRRT);

    // And that the non-preferred location did not get touched
    XCTAssertEqualObjects([self.ADALTokenCache getMRRT:authority], s_doNotUseRT);
    XCTAssertNil([self.ADALTokenCache getFRT:authority]);
    XCTAssertNil([self.ADALTokenCache getAT:authority]);
}

@end


