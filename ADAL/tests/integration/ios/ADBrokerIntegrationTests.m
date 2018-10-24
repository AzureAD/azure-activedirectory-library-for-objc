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

#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>
#import <XCTest/XCTest.h>
#import "XCTestCase+TestHelperMethods.h"

#import "NSDictionary+ADExtensions.h"
#import "NSString+ADHelperMethods.h"
#import "NSURL+ADTestUtil.h"

#import "ADApplicationTestUtil.h"
#import "ADAuthenticationContext+Internal.h"
#import "ADBrokerHelper.h"
#import "ADBrokerKeyHelper.h"
#import "ADKeychainTokenCache+Internal.h"
#import "ADTokenCache+Internal.h"
#import "ADTokenCacheItem.h"
#import "ADTokenCacheTestUtil.h"
#import "ADUserInformation.h"
#import "ADRefreshResponseBuilder.h"
#import "ADEnrollmentGateway.h"
#import "ADEnrollmentGateway+TestUtil.h"

@interface ADEnrollmentGateway ()

+ (void)setEnrollmentIdsWithJsonBlob:(NSString *)enrollmentIds;
+ (void)setIntuneMAMResourceWithJsonBlob:(NSString *)resources;

@end

@interface ADBrokerIntegrationTests : ADTestCase

@end

@implementation ADBrokerIntegrationTests

- (void)setUp {
    [super setUp];
    [[ADKeychainTokenCache keychainCacheForGroup:nil] testRemoveAll:nil];
}

- (void)tearDown {
    [super tearDown];
}

+ (NSURL *)createV2BrokerResponse:(NSDictionary *)parameters
                      redirectUri:(NSString *)redirectUri
{
    NSDictionary* message = [ADBrokerIntegrationTests createV2BrokerResponseDicitonary:parameters];
    
    return [NSURL URLWithString:[NSString stringWithFormat:@"%@?%@", redirectUri, [message adURLFormEncode]]];
}

+ (NSURL *)createV2BrokerErrorResponse:(NSDictionary *)parameters
                           redirectUri:(NSString *)redirectUri
{
    return [NSURL URLWithString:[NSString stringWithFormat:@"%@?%@", redirectUri, [parameters adURLFormEncode]]];
}

+ (NSDictionary *) createV2BrokerResponseDicitonary:(NSDictionary *) parameters
{
    NSData *payload = [[parameters adURLFormEncode] dataUsingEncoding:NSUTF8StringEncoding];
    NSData *brokerKey = [ADBrokerKeyHelper symmetricKey];

    size_t bufferSize = [payload length] + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesEncrypted = 0;

    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                                          [brokerKey bytes], kCCKeySizeAES256,
                                          NULL /* initialization vector (optional) */,
                                          [payload bytes], [payload length], /* input */
                                          buffer, bufferSize, /* output */
                                          &numBytesEncrypted);
    if (cryptStatus != kCCSuccess)
    {
        return nil;
    }

    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256([payload bytes], (CC_LONG)[payload length], hash);
    NSMutableString *fingerprint = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 3];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; ++i)
    {
        [fingerprint appendFormat:@"%02x", hash[i]];
    }

    NSDictionary *message =
    @{
      @"msg_protocol_ver" : @"2",
      @"response" :  [NSString adBase64UrlEncodeData:[NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted]],
      @"hash" : [fingerprint uppercaseString],
      };

    return message;
}

- (ADAuthenticationContext *)getBrokerTestContext:(NSString *)authority
{
    ADAuthenticationContext *context =
    [[ADAuthenticationContext alloc] initWithAuthority:authority
                                     validateAuthority:YES
                                           sharedGroup:nil
                                                 error:nil];
    
    NSAssert(context, @"If this is failing for whatever reason you should probably fix it before trying to run tests.");
    [context setCorrelationId:TEST_CORRELATION_ID];
    [context setCredentialsType:AD_CREDENTIALS_AUTO];
    
    return context;
}

- (void)testBroker_whenSimpleAcquireToken_shouldSucceed
{
    NSString *authority = @"https://login.windows.net/common";
    NSString *brokerKey = @"BU-bLN3zTfHmyhJ325A8dJJ1tzrnKMHEfsTlStdMo0U";
    NSString *redirectUri = @"x-msauth-unittest://com.microsoft.unittesthost";
    [ADBrokerKeyHelper setSymmetricKey:brokerKey];
    
    [ADApplicationTestUtil onOpenURL:^BOOL(NSURL *url, NSDictionary<NSString *,id> *options) {
        (void)options;
        
        NSDictionary *expectedParams =
        @{
          @"authority" : authority,
          @"resource" : TEST_RESOURCE,
          @"username_type" : @"",
          @"max_protocol_ver" : @"2",
          @"broker_key" : brokerKey,
          @"client_version" : ADAL_VERSION_NSSTRING,
          @"force" : @"NO",
          @"redirect_uri" : redirectUri,
          @"username" : @"",
          @"client_id" : TEST_CLIENT_ID,
          @"correlation_id" : TEST_CORRELATION_ID,
          @"skip_cache" : @"NO",
          @"extra_qp" : @"",
          @"claims" : @"",
          @"intune_enrollment_ids" : @"",
          @"intune_mam_resource" : @"",
          @"client_capabilities" : @"",
          @"client_app_name": @"UnitTestHostApp",
          @"client_app_version": @"1.0"
          };
        
        NSString *expectedUrlString = [NSString stringWithFormat:@"msauth://broker?%@", [expectedParams adURLFormEncode]];
        NSURL *expectedURL = [NSURL URLWithString:expectedUrlString];
        XCTAssertTrue([expectedURL matchesURL:url]);
        
        NSDictionary *responseParams =
        @{
          @"authority" : authority,
          @"resource" : TEST_RESOURCE,
          @"client_id" : TEST_CLIENT_ID,
          @"id_token" : [[self adCreateUserInformation:TEST_USER_ID] rawIdToken],
          @"access_token" : @"i-am-a-access-token",
          @"refresh_token" : @"i-am-a-refresh-token",
          @"foci" : @"1",
          @"expires_in" : @"3600"
          };
        
        [ADAuthenticationContext handleBrokerResponse:[ADBrokerIntegrationTests createV2BrokerResponse:responseParams redirectUri:redirectUri]];
        return YES;
    }];
    
    NSArray *metadata = @[ @{ @"preferred_network" : @"login.microsoftonline.com",
                              @"preferred_cache" : @"login.windows.net",
                              @"aliases" : @[ @"login.windows.net", @"login.microsoftonline.com"] } ];
    ADTestURLResponse *validationResponse =
    [ADTestAuthorityValidationResponse validAuthority:authority
                                          trustedHost:@"login.windows.net"
                                         withMetadata:metadata];
    [ADTestURLSession addResponses:@[validationResponse]];
    
    ADAuthenticationContext *context = [self getBrokerTestContext:authority];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquire token callback"];
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:[NSURL URLWithString:redirectUri]
                      completionBlock:^(ADAuthenticationResult *result)
    {
        XCTAssertNotNil(result);
        XCTAssertEqual(result.status, AD_SUCCEEDED);
        
        XCTAssertEqualObjects(result.tokenCacheItem.accessToken, @"i-am-a-access-token");
        XCTAssertEqualObjects(result.tokenCacheItem.refreshToken, @"i-am-a-refresh-token");
        
        [expectation fulfill];
    }];
    
    [self waitForExpectations:@[expectation] timeout:1.0];
    
    ADKeychainTokenCache *tokenCache = (ADKeychainTokenCache *)[context tokenCacheStore].dataSource;
    
    XCTAssertEqualObjects([tokenCache getAT:authority], @"i-am-a-access-token");
    XCTAssertEqualObjects([tokenCache getMRRT:authority], @"i-am-a-refresh-token");
    XCTAssertEqualObjects([tokenCache getFRT:authority], @"i-am-a-refresh-token");
}

- (void)testBroker_whenFailWithProtectionRequiredError_shouldStoreMamTokenAndReturnError
{
    NSString *authority = @"https://login.windows.net/common";
    NSString *brokerKey = @"BU-bLN3zTfHmyhJ325A8dJJ1tzrnKMHEfsTlStdMo0U";
    NSString *redirectUri = @"x-msauth-unittest://com.microsoft.unittesthost";
    [ADBrokerKeyHelper setSymmetricKey:brokerKey];

    [ADApplicationTestUtil onOpenURL:^BOOL(NSURL *url, NSDictionary<NSString *,id> *options) {
        (void)options;

        NSDictionary *expectedParams =
        @{
          @"authority" : authority,
          @"resource" : TEST_RESOURCE,
          @"username_type" : @"",
          @"max_protocol_ver" : @"2",
          @"broker_key" : brokerKey,
          @"client_version" : ADAL_VERSION_NSSTRING,
          @"force" : @"NO",
          @"redirect_uri" : redirectUri,
          @"username" : @"",
          @"client_id" : TEST_CLIENT_ID,
          @"correlation_id" : TEST_CORRELATION_ID,
          @"skip_cache" : @"NO",
          @"extra_qp" : @"",
          @"claims" : @"",
          @"intune_enrollment_ids" : @"",
          @"intune_mam_resource" : @"",
          @"client_capabilities" : @"",
          @"client_app_name": @"UnitTestHostApp",
          @"client_app_version": @"1.0"
          };

        NSString *expectedUrlString = [NSString stringWithFormat:@"msauth://broker?%@", [expectedParams adURLFormEncode]];
        NSURL *expectedURL = [NSURL URLWithString:expectedUrlString];
        XCTAssertTrue([expectedURL matchesURL:url]);


        NSMutableDictionary *responseParams =
        [[NSMutableDictionary alloc] initWithDictionary:@{
                                                        @"error_code" : @"213", // AD_ERROR_SERVER_PROTECTION_POLICY_REQUIRED
                                                        @"error_description" : @"AADSTS53005: Application needs to enforce intune protection policies",
                                                        @"error" : @"unauthorized_client",
                                                        @"suberror" : @"protection_policies_required",
                                                        BROKER_APP_VERSION : @"2"
                                                        }];
        NSDictionary *intune_token_response = @{
                                              @"authority" : authority,
                                              @"resource" : TEST_RESOURCE,
                                              @"client_id" : TEST_CLIENT_ID,
                                              @"id_token" : [[self adCreateUserInformation:TEST_USER_ID] rawIdToken],
                                              @"access_token" : @"i-am-a-access-token",
                                              @"refresh_token" : @"i-am-a-refresh-token",
                                              @"foci" : @"1",
                                              @"expires_in" : @"3600"};
        NSDictionary* encrypted_token = [ADBrokerIntegrationTests createV2BrokerResponseDicitonary:intune_token_response];

        [responseParams setValue:encrypted_token[BROKER_RESPONSE_KEY] forKey:BROKER_INTUNE_RESPONSE_KEY];
        [responseParams setValue:encrypted_token[BROKER_HASH_KEY] forKey:BROKER_INTUNE_HASH_KEY];
        [responseParams setValue:encrypted_token[@"msg_protocol_ver"] forKey:@"msg_protocol_ver"];

        [ADAuthenticationContext handleBrokerResponse:[ADBrokerIntegrationTests createV2BrokerErrorResponse:responseParams redirectUri:redirectUri]];
        return YES;
    }];

    NSArray *metadata = @[ @{ @"preferred_network" : @"login.microsoftonline.com",
                              @"preferred_cache" : @"login.windows.net",
                              @"aliases" : @[ @"login.windows.net", @"login.microsoftonline.com"] } ];
    ADTestURLResponse *validationResponse =
    [ADTestAuthorityValidationResponse validAuthority:authority
                                          trustedHost:@"login.windows.net"
                                         withMetadata:metadata];
    [ADTestURLSession addResponses:@[validationResponse]];

    ADAuthenticationContext *context = [self getBrokerTestContext:authority];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquire token callback"];
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:[NSURL URLWithString:redirectUri]
                      completionBlock:^(ADAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertEqual(result.error.code, AD_ERROR_SERVER_PROTECTION_POLICY_REQUIRED);
         XCTAssertEqualObjects(result.error.userInfo[ADSuberrorKey], @"protection_policies_required");
         XCTAssertEqualObjects(result.error.userInfo[ADBrokerVersionKey], @"2");
         XCTAssertEqualObjects(result.error.userInfo[ADUserIdKey], [[self adCreateUserInformation:TEST_USER_ID] userId]);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1.0];

    // Assert that MAM token was added to cache even though broker returned an error code
    ADKeychainTokenCache *tokenCache = (ADKeychainTokenCache *)[context tokenCacheStore].dataSource;

    XCTAssertEqualObjects([tokenCache getAT:authority], @"i-am-a-access-token");
    XCTAssertEqualObjects([tokenCache getMRRT:authority], @"i-am-a-refresh-token");
    XCTAssertEqualObjects([tokenCache getFRT:authority], @"i-am-a-refresh-token");
}

- (void)testBroker_whenClaimsChallengePassed_shouldSucceedAndPassSkipCacheYES
{
    NSString *authority = @"https://login.windows.net/common";
    NSString *brokerKey = @"BU-bLN3zTfHmyhJ325A8dJJ1tzrnKMHEfsTlStdMo0U";
    NSString *redirectUri = @"x-msauth-unittest://com.microsoft.unittesthost";
    [ADBrokerKeyHelper setSymmetricKey:brokerKey];

    [ADApplicationTestUtil onOpenURL:^BOOL(NSURL *url, NSDictionary<NSString *,id> *options) {
        (void)options;

        NSDictionary *expectedParams =
        @{
          @"authority" : authority,
          @"resource" : TEST_RESOURCE,
          @"username_type" : @"",
          @"max_protocol_ver" : @"2",
          @"broker_key" : brokerKey,
          @"client_version" : ADAL_VERSION_NSSTRING,
          @"force" : @"NO",
          @"redirect_uri" : redirectUri,
          @"username" : @"",
          @"client_id" : TEST_CLIENT_ID,
          @"correlation_id" : TEST_CORRELATION_ID,
          @"skip_cache" : @"YES",
          @"extra_qp" : @"",
          @"claims" : @"%7B%22access_token%22%3A%7B%22deviceid%22%3A%7B%22essential%22%3Atrue%7D%7D%7D",
          @"intune_enrollment_ids" : @"",
          @"intune_mam_resource" : @"",
          @"client_capabilities" : @"",
          @"client_app_name": @"UnitTestHostApp",
          @"client_app_version": @"1.0"
          };

        NSString *expectedUrlString = [NSString stringWithFormat:@"msauth://broker?%@", [expectedParams adURLFormEncode]];
        NSURL *expectedURL = [NSURL URLWithString:expectedUrlString];
        XCTAssertTrue([expectedURL matchesURL:url]);

        NSDictionary *responseParams =
        @{
          @"authority" : authority,
          @"resource" : TEST_RESOURCE,
          @"client_id" : TEST_CLIENT_ID,
          @"id_token" : [[self adCreateUserInformation:TEST_USER_ID] rawIdToken],
          @"access_token" : @"result-broker-at",
          @"refresh_token" : @"result-broker-rt",
          @"foci" : @"1",
          @"expires_in" : @"3600"
          };

        [ADAuthenticationContext handleBrokerResponse:[ADBrokerIntegrationTests createV2BrokerResponse:responseParams redirectUri:redirectUri]];
        return YES;
    }];

    NSArray *metadata = @[ @{ @"preferred_network" : @"login.microsoftonline.com",
                              @"preferred_cache" : @"login.windows.net",
                              @"aliases" : @[ @"login.windows.net", @"login.microsoftonline.com"] } ];
    ADTestURLResponse *validationResponse =
    [ADTestAuthorityValidationResponse validAuthority:authority
                                          trustedHost:@"login.windows.net"
                                         withMetadata:metadata];
    [ADTestURLSession addResponses:@[validationResponse]];

    ADAuthenticationContext *context = [self getBrokerTestContext:authority];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquire token callback"];
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:[NSURL URLWithString:redirectUri]
                       promptBehavior:AD_PROMPT_ALWAYS
                       userIdentifier:nil
                 extraQueryParameters:nil
                               claims:@"%7B%22access_token%22%3A%7B%22deviceid%22%3A%7B%22essential%22%3Atrue%7D%7D%7D"
                      completionBlock:^(ADAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);

         XCTAssertEqualObjects(result.tokenCacheItem.accessToken, @"result-broker-at");
         XCTAssertEqualObjects(result.tokenCacheItem.refreshToken, @"result-broker-rt");

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1.0];
}

- (void)testBroker_whenFailWithProtectionRequiredErrorWithoutToken_shouldReturnErrorWithoutToken
{
    NSString *authority = @"https://login.windows.net/common";
    NSString *brokerKey = @"BU-bLN3zTfHmyhJ325A8dJJ1tzrnKMHEfsTlStdMo0U";
    NSString *redirectUri = @"x-msauth-unittest://com.microsoft.unittesthost";
    [ADBrokerKeyHelper setSymmetricKey:brokerKey];

    [ADApplicationTestUtil onOpenURL:^BOOL(NSURL *url, NSDictionary<NSString *,id> *options) {
        (void)options;

        NSDictionary *expectedParams =
        @{
          @"authority" : authority,
          @"resource" : TEST_RESOURCE,
          @"username_type" : @"",
          @"max_protocol_ver" : @"2",
          @"broker_key" : brokerKey,
          @"client_version" : ADAL_VERSION_NSSTRING,
          @"force" : @"NO",
          @"redirect_uri" : redirectUri,
          @"username" : @"",
          @"client_id" : TEST_CLIENT_ID,
          @"correlation_id" : TEST_CORRELATION_ID,
          @"skip_cache" : @"NO",
          @"extra_qp" : @"",
          @"claims" : @"",
          @"intune_enrollment_ids" : @"",
          @"intune_mam_resource" : @"",
          @"client_capabilities" : @"",
          @"client_app_name": @"UnitTestHostApp",
          @"client_app_version": @"1.0"
          };

        NSString *expectedUrlString = [NSString stringWithFormat:@"msauth://broker?%@", [expectedParams adURLFormEncode]];
        NSURL *expectedURL = [NSURL URLWithString:expectedUrlString];
        XCTAssertTrue([expectedURL matchesURL:url]);


        NSMutableDictionary *responseParams =
        [[NSMutableDictionary alloc] initWithDictionary:@{
                                                          @"error_code" : @"213", // AD_ERROR_SERVER_PROTECTION_POLICY_REQUIRED
                                                          @"error_description" : @"AADSTS53005: Application needs to enforce intune protection policies",
                                                          @"error" : @"unauthorized_client",
                                                          @"suberror" : @"protection_policies_required",
                                                          }];

        [ADAuthenticationContext handleBrokerResponse:[ADBrokerIntegrationTests createV2BrokerErrorResponse:responseParams redirectUri:redirectUri]];
        return YES;
    }];

    NSArray *metadata = @[ @{ @"preferred_network" : @"login.microsoftonline.com",
                              @"preferred_cache" : @"login.windows.net",
                              @"aliases" : @[ @"login.windows.net", @"login.microsoftonline.com"] } ];
    ADTestURLResponse *validationResponse =
    [ADTestAuthorityValidationResponse validAuthority:authority
                                          trustedHost:@"login.windows.net"
                                         withMetadata:metadata];
    [ADTestURLSession addResponses:@[validationResponse]];

    ADAuthenticationContext *context = [self getBrokerTestContext:authority];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquire token callback"];
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:[NSURL URLWithString:redirectUri]
                      completionBlock:^(ADAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertEqual(result.error.code, AD_ERROR_SERVER_PROTECTION_POLICY_REQUIRED);

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1.0];

    // Assert that MAM token was added to cache even though broker returned an error code
    ADKeychainTokenCache *tokenCache = (ADKeychainTokenCache *)[context tokenCacheStore].dataSource;

    XCTAssertNil([tokenCache getAT:authority]);
    XCTAssertNil([tokenCache getMRRT:authority]);
    XCTAssertNil([tokenCache getFRT:authority]);
}

- (void)testBroker_whenTenantSpecified_shouldGetNewAT
{
    NSString *authority = @"https://login.microsoftonline.com/contoso.net";
    NSString *cacheAuthority = @"https://login.windows.net/contoso.net";
    NSString *brokerKey = @"BU-bLN3zTfHmyhJ325A8dJJ1tzrnKMHEfsTlStdMo0U";
    NSString *redirectUri = @"x-msauth-unittest://com.microsoft.unittesthost";
    NSString *brokerRT = @"i-am-a-refresh-token";
    NSString *brokerAT = @"i-am-a-access-token";
    NSString *updatedRT = @"updated-refresh-token";
    NSString *updatedAT = @"updated-access-token";
    NSString *correctTid = @"4b93453c-1131-4828-9715-a2e83336f2f2";
    
    [ADBrokerKeyHelper setSymmetricKey:brokerKey];
    
    // Parameters for launching broker
    [ADApplicationTestUtil onOpenURL:^BOOL(NSURL *url, NSDictionary<NSString *,id> *options) {
        (void)options;
        
        NSDictionary *expectedParams =
        @{
          @"authority" : authority,
          @"resource" : TEST_RESOURCE,
          @"username_type" : @"",
          @"max_protocol_ver" : @"2",
          @"broker_key" : brokerKey,
          @"client_version" : ADAL_VERSION_NSSTRING,
          @"force" : @"NO",
          @"redirect_uri" : redirectUri,
          @"username" : @"",
          @"client_id" : TEST_CLIENT_ID,
          @"correlation_id" : TEST_CORRELATION_ID,
          @"skip_cache" : @"NO",
          @"extra_qp" : @"",
          @"claims" : @"",
          @"intune_enrollment_ids" : @"",
          @"intune_mam_resource" : @"",
          @"client_capabilities" : @"",
          @"client_app_name": @"UnitTestHostApp",
          @"client_app_version": @"1.0"
          };
        
        NSString *expectedUrlString = [NSString stringWithFormat:@"msauth://broker?%@", [expectedParams adURLFormEncode]];
        NSURL *expectedURL = [NSURL URLWithString:expectedUrlString];
        XCTAssertTrue([expectedURL matchesURL:url]);
        
        // Broker response back to client
        NSDictionary *responseParams =
        @{
          @"authority" : authority,
          @"resource" : TEST_RESOURCE,
          @"client_id" : TEST_CLIENT_ID,
          @"id_token" : [[self adCreateUserInformation:TEST_USER_ID] rawIdToken],
          @"access_token" : brokerAT,
          @"refresh_token" : brokerRT,
          @"foci" : @"1",
          @"expires_in" : @"3600"
          };
        
        [ADAuthenticationContext handleBrokerResponse:[ADBrokerIntegrationTests createV2BrokerResponse:responseParams redirectUri:redirectUri]];
        return YES;
    }];
    
    NSArray *metadata = @[ @{ @"preferred_network" : @"login.microsoftonline.com",
                              @"preferred_cache" : @"login.windows.net",
                              @"aliases" : @[ @"login.windows.net", @"login.microsoftonline.com"] } ];
    ADTestURLResponse *validationResponse =
    [ADTestAuthorityValidationResponse validAuthority:authority
                                          trustedHost:@"login.microsoftonline.com"
                                         withMetadata:metadata];
    
    ADRefreshResponseBuilder *builder = [ADRefreshResponseBuilder new];
    builder.oldRefreshToken = brokerRT;
    builder.authority = authority;
    builder.requestBody[@"scope"] = @"openid";
    builder.updatedRefreshToken = updatedRT;
    builder.updatedAccessToken = updatedAT;
    builder.responseBody[@"foci"] = @"1";
    builder.updatedIdToken = [[XCTestCase adCreateUserInformation:TEST_USER_ID tenantId:correctTid] rawIdToken];
    ADTestURLResponse *tokenResponse = builder.response;
    [ADTestURLSession addResponses:@[validationResponse, tokenResponse]];
    
    ADAuthenticationContext *context = [self getBrokerTestContext:authority];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquire token callback"];
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:[NSURL URLWithString:redirectUri]
                      completionBlock:^(ADAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         
         XCTAssertEqualObjects(result.tokenCacheItem.accessToken, updatedAT);
         XCTAssertEqualObjects(result.tokenCacheItem.refreshToken, updatedRT);
         
         [expectation fulfill];
     }];
    
    [self waitForExpectations:@[expectation] timeout:1.0];
    
    ADKeychainTokenCache *tokenCache = (ADKeychainTokenCache *)[context tokenCacheStore].dataSource;
    
    XCTAssertEqualObjects([tokenCache getAT:cacheAuthority], updatedAT);
    XCTAssertEqualObjects([tokenCache getMRRT:cacheAuthority], updatedRT);
    XCTAssertEqualObjects([tokenCache getMRRTItem:cacheAuthority].userInformation.tenantId, correctTid);
    XCTAssertEqualObjects([tokenCache getFRT:cacheAuthority], updatedRT);
    XCTAssertEqualObjects([tokenCache getFRTItem:cacheAuthority].userInformation.tenantId, correctTid);
}

- (void)testBroker_whenTenantSpecifiedWithRequestUsingScope_shouldGetNewAT
{
    // This test is near identical to testBroker_whenTenantSpecified_shouldGetNewAT except the
    // acquireToken call is initiated using ADAuthenticationRequest directly
    NSString *authority = @"https://login.microsoftonline.com/contoso.net";
    NSString *cacheAuthority = @"https://login.windows.net/contoso.net";
    NSString *brokerKey = @"BU-bLN3zTfHmyhJ325A8dJJ1tzrnKMHEfsTlStdMo0U";
    NSString *redirectUri = @"x-msauth-unittest://com.microsoft.unittesthost";
    NSString *brokerRT = @"i-am-a-refresh-token";
    NSString *brokerAT = @"i-am-a-access-token";
    NSString *updatedRT = @"updated-refresh-token";
    NSString *updatedAT = @"updated-access-token";
    NSString *correctTid = @"4b93453c-1131-4828-9715-a2e83336f2f2";
    
    [ADBrokerKeyHelper setSymmetricKey:brokerKey];
    
    // Parameters for launching broker
    [ADApplicationTestUtil onOpenURL:^BOOL(NSURL *url, NSDictionary<NSString *,id> *options) {
        (void)options;
        
        NSDictionary *expectedParams =
        @{
          @"authority" : authority,
          @"resource" : TEST_RESOURCE,
          @"username_type" : @"",
          @"max_protocol_ver" : @"2",
          @"broker_key" : brokerKey,
          @"client_version" : ADAL_VERSION_NSSTRING,
          @"force" : @"NO",
          @"redirect_uri" : redirectUri,
          @"username" : @"",
          @"client_id" : TEST_CLIENT_ID,
          @"correlation_id" : TEST_CORRELATION_ID,
          @"skip_cache" : @"NO",
          @"extra_qp" : @"",
          @"claims" : @"",
          @"intune_enrollment_ids" : @"",
          @"intune_mam_resource" : @"",
          @"client_capabilities" : @"",
          @"client_app_name": @"UnitTestHostApp",
          @"client_app_version": @"1.0"
          };
        
        NSString *expectedUrlString = [NSString stringWithFormat:@"msauth://broker?%@", [expectedParams adURLFormEncode]];
        NSURL *expectedURL = [NSURL URLWithString:expectedUrlString];
        XCTAssertTrue([expectedURL matchesURL:url]);
        
        // Broker response back to client
        NSDictionary *responseParams =
        @{
          @"authority" : authority,
          @"resource" : TEST_RESOURCE,
          @"client_id" : TEST_CLIENT_ID,
          @"id_token" : [[self adCreateUserInformation:TEST_USER_ID] rawIdToken],
          @"access_token" : brokerAT,
          @"refresh_token" : brokerRT,
          @"foci" : @"1",
          @"expires_in" : @"3600"
          };
        
        [ADAuthenticationContext handleBrokerResponse:[ADBrokerIntegrationTests createV2BrokerResponse:responseParams redirectUri:redirectUri]];
        return YES;
    }];
    
    NSArray *metadata = @[ @{ @"preferred_network" : @"login.microsoftonline.com",
                              @"preferred_cache" : @"login.windows.net",
                              @"aliases" : @[ @"login.windows.net", @"login.microsoftonline.com"] } ];
    ADTestURLResponse *validationResponse =
    [ADTestAuthorityValidationResponse validAuthority:authority
                                          trustedHost:@"login.microsoftonline.com"
                                         withMetadata:metadata];
    
    ADRefreshResponseBuilder *builder = [ADRefreshResponseBuilder new];
    builder.oldRefreshToken = brokerRT;
    builder.authority = authority;
    builder.requestBody[@"scope"] = @"openid aza bzb";
    builder.updatedRefreshToken = updatedRT;
    builder.updatedAccessToken = updatedAT;
    builder.responseBody[@"foci"] = @"1";
    builder.updatedIdToken = [[XCTestCase adCreateUserInformation:TEST_USER_ID tenantId:correctTid] rawIdToken];
    ADTestURLResponse *tokenResponse = builder.response;
    [ADTestURLSession addResponses:@[validationResponse, tokenResponse]];
    
    ADAuthenticationContext *context = [self getBrokerTestContext:authority];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquire token callback"];
    
    ADAuthenticationRequest *req = [ADAuthenticationRequest requestWithContext:context];
    req.requestParams.resource = TEST_RESOURCE;
    req.requestParams.clientId = TEST_CLIENT_ID;
    req.requestParams.redirectUri = redirectUri;
    req.requestParams.scope = @"aza bzb";
    
    [req acquireToken:@"1234567890"
      completionBlock:^(ADAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         
         XCTAssertEqualObjects(result.tokenCacheItem.accessToken, updatedAT);
         XCTAssertEqualObjects(result.tokenCacheItem.refreshToken, updatedRT);
         
         [expectation fulfill];
     }];
    
    [self waitForExpectations:@[expectation] timeout:1.0];
    
    ADKeychainTokenCache *tokenCache = (ADKeychainTokenCache *)[context tokenCacheStore].dataSource;
    XCTAssertEqualObjects([tokenCache getAT:cacheAuthority], updatedAT);
    XCTAssertEqualObjects([tokenCache getMRRT:cacheAuthority], updatedRT);
    XCTAssertEqualObjects([tokenCache getMRRTItem:cacheAuthority].userInformation.tenantId, correctTid);
    XCTAssertEqualObjects([tokenCache getFRT:cacheAuthority], updatedRT);
    XCTAssertEqualObjects([tokenCache getFRTItem:cacheAuthority].userInformation.tenantId, correctTid);
}

- (void)testBroker_whenEnrollmentIDandMAMResourceIDArePresent_shouldSucceed
{
    [ADEnrollmentGateway setIntuneMAMResourceWithJsonBlob:[ADEnrollmentGateway getTestResourceJSON]];
    [ADEnrollmentGateway setEnrollmentIdsWithJsonBlob:[ADEnrollmentGateway getTestEnrollmentIDJSON]];

    NSString *authority = @"https://login.windows.net/common";
    NSString *brokerKey = @"BU-bLN3zTfHmyhJ325A8dJJ1tzrnKMHEfsTlStdMo0U";
    NSString *redirectUri = @"x-msauth-unittest://com.microsoft.unittesthost";
    NSString *enrollmentIDs = [ADEnrollmentGateway getTestEnrollmentIDJSON];
    NSString *intuneResource = [ADEnrollmentGateway getTestResourceJSON];
    [ADBrokerKeyHelper setSymmetricKey:brokerKey];

    [ADApplicationTestUtil onOpenURL:^BOOL(NSURL *url, NSDictionary<NSString *,id> *options) {
        (void)options;

        NSDictionary *expectedParams =
        @{
          @"authority" : authority,
          @"resource" : TEST_RESOURCE,
          @"username_type" : @"",
          @"max_protocol_ver" : @"2",
          @"broker_key" : brokerKey,
          @"client_version" : ADAL_VERSION_NSSTRING,
          @"force" : @"NO",
          @"redirect_uri" : redirectUri,
          @"username" : @"",
          @"client_id" : TEST_CLIENT_ID,
          @"correlation_id" : TEST_CORRELATION_ID,
          @"skip_cache" : @"NO",
          @"extra_qp" : @"",
          @"claims" : @"",
          @"intune_enrollment_ids" : enrollmentIDs,
          @"intune_mam_resource" : intuneResource,
          @"client_capabilities" : @"",
          @"client_app_name": @"UnitTestHostApp",
          @"client_app_version": @"1.0"
          };

        NSString *expectedUrlString = [NSString stringWithFormat:@"msauth://broker?%@", [expectedParams adURLFormEncode]];
        NSURL *expectedURL = [NSURL URLWithString:expectedUrlString];
        XCTAssertTrue([expectedURL matchesURL:url]);

        NSDictionary *responseParams =
        @{
          @"authority" : authority,
          @"resource" : TEST_RESOURCE,
          @"client_id" : TEST_CLIENT_ID,
          @"id_token" : [[self adCreateUserInformation:TEST_USER_ID] rawIdToken],
          @"access_token" : @"i-am-a-access-token",
          @"refresh_token" : @"i-am-a-refresh-token",
          @"foci" : @"1",
          @"expires_in" : @"3600"
          };

        [ADAuthenticationContext handleBrokerResponse:[ADBrokerIntegrationTests createV2BrokerResponse:responseParams redirectUri:redirectUri]];
        return YES;
    }];

    NSArray *metadata = @[ @{ @"preferred_network" : @"login.microsoftonline.com",
                              @"preferred_cache" : @"login.windows.net",
                              @"aliases" : @[ @"login.windows.net", @"login.microsoftonline.com"] } ];
    ADTestURLResponse *validationResponse =
    [ADTestAuthorityValidationResponse validAuthority:authority
                                          trustedHost:@"login.windows.net"
                                         withMetadata:metadata];
    [ADTestURLSession addResponses:@[validationResponse]];

    ADAuthenticationContext *context = [self getBrokerTestContext:authority];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquire token callback"];
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:[NSURL URLWithString:redirectUri]
                      completionBlock:^(ADAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);

         XCTAssertEqualObjects(result.tokenCacheItem.accessToken, @"i-am-a-access-token");
         XCTAssertEqualObjects(result.tokenCacheItem.refreshToken, @"i-am-a-refresh-token");

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1.0];

    ADKeychainTokenCache *tokenCache = (ADKeychainTokenCache *)[context tokenCacheStore].dataSource;

    XCTAssertEqualObjects([tokenCache getAT:authority], @"i-am-a-access-token");
    XCTAssertEqualObjects([tokenCache getMRRT:authority], @"i-am-a-refresh-token");
    XCTAssertEqualObjects([tokenCache getFRT:authority], @"i-am-a-refresh-token");

    [ADEnrollmentGateway setIntuneMAMResourceWithJsonBlob:@""];
    [ADEnrollmentGateway setEnrollmentIdsWithJsonBlob:@""];

}

- (void)testBroker_whenClientCapabilitiesPresent_shouldSucceed
{
    NSString *authority = @"https://login.windows.net/common";
    NSString *brokerKey = @"BU-bLN3zTfHmyhJ325A8dJJ1tzrnKMHEfsTlStdMo0U";
    NSString *redirectUri = @"x-msauth-unittest://com.microsoft.unittesthost";
    [ADBrokerKeyHelper setSymmetricKey:brokerKey];

    [ADApplicationTestUtil onOpenURL:^BOOL(NSURL *url, NSDictionary<NSString *,id> *options) {
        (void)options;

        NSDictionary *expectedParams =
        @{
          @"authority" : authority,
          @"resource" : TEST_RESOURCE,
          @"username_type" : @"RequiredDisplayableId",
          @"max_protocol_ver" : @"2",
          @"broker_key" : brokerKey,
          @"client_version" : ADAL_VERSION_NSSTRING,
          @"force" : @"NO",
          @"redirect_uri" : redirectUri,
          @"username" : @"",
          @"client_id" : TEST_CLIENT_ID,
          @"correlation_id" : TEST_CORRELATION_ID,
          @"skip_cache" : @"NO",
          @"extra_qp" : @"",
          @"claims" : @"",
          @"intune_enrollment_ids" : @"",
          @"intune_mam_resource" : @"",
          @"client_capabilities": @"llt",
          @"client_app_name": @"UnitTestHostApp",
          @"client_app_version": @"1.0"
          };

        NSString *expectedUrlString = [NSString stringWithFormat:@"msauth://broker?%@", [expectedParams adURLFormEncode]];
        NSURL *expectedURL = [NSURL URLWithString:expectedUrlString];
        XCTAssertTrue([expectedURL matchesURL:url]);

        NSDictionary *responseParams =
        @{
          @"authority" : authority,
          @"resource" : TEST_RESOURCE,
          @"client_id" : TEST_CLIENT_ID,
          @"id_token" : [[self adCreateUserInformation:TEST_USER_ID] rawIdToken],
          @"access_token" : @"i-am-a-access-token",
          @"refresh_token" : @"i-am-a-refresh-token",
          @"foci" : @"1",
          @"expires_in" : @"3600"
          };

        [ADAuthenticationContext handleBrokerResponse:[ADBrokerIntegrationTests createV2BrokerResponse:responseParams redirectUri:redirectUri]];
        return YES;
    }];

    NSArray *metadata = @[ @{ @"preferred_network" : @"login.microsoftonline.com",
                              @"preferred_cache" : @"login.windows.net",
                              @"aliases" : @[ @"login.windows.net", @"login.microsoftonline.com"] } ];
    ADTestURLResponse *validationResponse =
    [ADTestAuthorityValidationResponse validAuthority:authority
                                          trustedHost:@"login.windows.net"
                                         withMetadata:metadata];
    [ADTestURLSession addResponses:@[validationResponse]];

    ADAuthenticationContext *context = [self getBrokerTestContext:authority];
    context.clientCapabilities = @[@"llt"];

    XCTestExpectation *expectation = [self expectationWithDescription:@"acquire token callback"];
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:[NSURL URLWithString:redirectUri]
                       promptBehavior:AD_PROMPT_ALWAYS
                               userId:nil
                 extraQueryParameters:nil
                      completionBlock:^(ADAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_SUCCEEDED);

         XCTAssertEqualObjects(result.tokenCacheItem.accessToken, @"i-am-a-access-token");
         XCTAssertEqualObjects(result.tokenCacheItem.refreshToken, @"i-am-a-refresh-token");

         [expectation fulfill];
     }];

    [self waitForExpectations:@[expectation] timeout:1.0];

}

@end
