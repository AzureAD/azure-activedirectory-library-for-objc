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
#import <Security/Security.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonDigest.h>
#import "ADBrokerNotificationManager.h"
#import "ADBrokerKeyHelper.h"
#import "MSIDPkeyAuthHelper.h"
#import "XCTestCase+TestHelperMethods.h"
#import "ADUserInformation.h"
#import "ADTokenCacheItem.h"
#import "ADAuthenticationContext+Internal.h"

@interface ADBrokerMessageTests : ADTestCase

@end

@implementation ADBrokerMessageTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [ADBrokerKeyHelper setSymmetricKey:nil];
    
    [super tearDown];
}

- (void)testBrokerResponse_whenNotFromBroker_shouldFailWithError
{
    // Set a redirect in the resume dictionary to make sure we at least try to process this message
    NSDictionary* resumeDictionary = @{ @"redirect_uri" : @"ms-outlook://", @"broker_nonce" : @"nonce" };
    [[NSUserDefaults standardUserDefaults] setObject:resumeDictionary forKey:kAdalResumeDictionaryKey];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"Non broker response."];
    [ADBrokerNotificationManager.sharedInstance enableNotifications:^(ADAuthenticationResult *result)
    {
        XCTAssertNotNil(result);
        XCTAssertNotNil(result.error);
        XCTAssertEqual(result.error.code, AD_ERROR_TOKENBROKER_HASH_MISSING);
        
        [expectation fulfill];
    }];
    
    // This should not crash and return NO
    XCTAssertFalse([ADAuthenticationContext handleBrokerResponse:[NSURL URLWithString:@"ms-outlook://settings/help/intunediagnostics?source=authenticator"] sourceApplication:nil]);
    
    [self waitForExpectationsWithTimeout:1.0 handler:nil];
}

- (void)testBrokerResponse_whenCorrectSourceApplication_andIncorrectResponseFormat_shouldFailWithError
{
    // Set a redirect in the resume dictionary to make sure we at least try to process this message
    NSDictionary* resumeDictionary = @{ @"redirect_uri" : @"ms-outlook://", @"broker_nonce" : @"nonce" };
    [[NSUserDefaults standardUserDefaults] setObject:resumeDictionary forKey:kAdalResumeDictionaryKey];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"Non broker response."];
    [ADBrokerNotificationManager.sharedInstance enableNotifications:^(ADAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_TOKENBROKER_HASH_MISSING);
         
         [expectation fulfill];
     }];
    
    // This should not crash and return NO
    XCTAssertFalse([ADAuthenticationContext handleBrokerResponse:[NSURL URLWithString:@"ms-outlook://settings/help/intunediagnostics?source=authenticator"] sourceApplication:ADAL_BROKER_APP_BUNDLE_ID]);
    
    [self waitForExpectationsWithTimeout:1.0 handler:nil];
}

- (void)testNonBrokerResponseMismatchedRedirectUri
{
    // Set a redirect in the resume dictionary to make sure we at least try to process this message
    NSDictionary* resumeDictionary = @{ @"redirect_uri" : @"different-redirect-uri://", @"broker_nonce" : @"nonce"  };
    [[NSUserDefaults standardUserDefaults] setObject:resumeDictionary forKey:kAdalResumeDictionaryKey];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"Non broker response with mismatched redirect uri."];
    [ADBrokerNotificationManager.sharedInstance enableNotifications:^(ADAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_TOKENBROKER_MISMATCHED_RESUME_STATE);
         
         [expectation fulfill];
     }];
    
    // This should not crash and return NO
    XCTAssertFalse([ADAuthenticationContext handleBrokerResponse:[NSURL URLWithString:@"ms-outlook://settings/help/intunediagnostics?source=authenticator"] sourceApplication:ADAL_BROKER_APP_BUNDLE_ID]);
    
    [self waitForExpectationsWithTimeout:1.0 handler:nil];
}

- (void)testBrokerResponse_whenNonceMissingInResumeDict_shouldFailWithError
{
    // Set a redirect in the resume dictionary to make sure we at least try to process this message
    NSDictionary* resumeDictionary = @{ @"redirect_uri" : @"ms-outlook://" };
    [[NSUserDefaults standardUserDefaults] setObject:resumeDictionary forKey:kAdalResumeDictionaryKey];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"Non broker response."];
    [ADBrokerNotificationManager.sharedInstance enableNotifications:^(ADAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_TOKENBROKER_BAD_RESUME_STATE);
         
         [expectation fulfill];
     }];
    
    // This should not crash and return NO
    XCTAssertFalse([ADAuthenticationContext handleBrokerResponse:[NSURL URLWithString:@"ms-outlook://settings/help/intunediagnostics?source=authenticator"] sourceApplication:ADAL_BROKER_APP_BUNDLE_ID]);
    
    [self waitForExpectationsWithTimeout:1.0 handler:nil];
}

- (void)testBrokerv2Message_whenSourceApplicationNonNil_andNonceMatches_shouldSucceed
{
    [ADBrokerKeyHelper setSymmetricKey:@"BU-bLN3zTfHmyhJ325A8dJJ1tzrnKMHEfsTlStdMo0U"];
    
    NSString* v2Base64UrlEncryptedPayload = @"UzLzGP78R7Ju4-5-YS23X-vNtZjkK4t2H7wULLZAZTzthtxGE5gHI95IZOIY7j_iUNG3fv57RSY8S8AQqT7KxXsIZ0k9XPKwXBqiOJG3-wUDLFMipvrFHUL5jg4MotNSdVNxEVl1H8kIWqJeGItEgRjPuTzVJir_Imog8aVImhq-pOPcN36kfNV_Cv9k8cBuqWDbHa5w8H8iUXBnIrI4cgfvqaxuO-lRcitf4xT3iaOMGzDMU2F2KpCTL3Rkt_tyYmUv_tqIamFnawXcVLcVfMVu3Zk8JuRZ0wUQn_zzUUu8VOfstQ9cSqhYHX1EnAhgX788b79FjcMzoY9C6VQoepB_uz9PEqOvR88Wnzkd9y5ubGJ7vCN03vSMxqDymowBzPTTCgz_rhNsWehnylzcz-W7Sx2UAGvXxhPvK7ny7IwlkroBjPm-gine4157_NMT";
    
    NSString* hash = @"752D8C22D3B0FCD5296E381B489901C1AFECD42F2380C908BC07F356E5BE333B";
    NSDictionary* resumeDictionary = @{ @"redirect_uri" : @"ms-outlook://", @"broker_nonce" : @"nonce"  };
    [[NSUserDefaults standardUserDefaults] setObject:resumeDictionary forKey:kAdalResumeDictionaryKey];
    
    NSDictionary* brokerMessage =
    @{
      @"msg_protocol_ver" : @"2",
      @"response" : v2Base64UrlEncryptedPayload,
      @"hash" : hash,
      };
    
    NSString* brokerUrlStr = [NSString stringWithFormat:@"ms-outlook://?%@", [brokerMessage msidWWWFormURLEncode]];
    NSURL* brokerUrl = [NSURL URLWithString:brokerUrlStr];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"Broker v2 message."];
    [ADBrokerNotificationManager.sharedInstance enableNotifications:^(ADAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertNil(result.error);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         
         XCTAssertEqualObjects(result.tokenCacheItem.resource, @"myfakeresource");
         XCTAssertNil(result.tokenCacheItem.accessToken);
         XCTAssertEqualObjects(result.tokenCacheItem.refreshToken, @"MyFakeRefreshToken");
         XCTAssertEqualObjects(result.tokenCacheItem.accessTokenType, @"Bearer");
         
         [expectation fulfill];
     }];
    
    XCTAssertTrue([ADAuthenticationContext handleBrokerResponse:brokerUrl sourceApplication:ADAL_BROKER_APP_BUNDLE_ID]);
    [self waitForExpectationsWithTimeout:1.0 handler:nil];
    
    XCTAssertNil([[NSUserDefaults standardUserDefaults] objectForKey:kAdalResumeDictionaryKey]);
}

- (void)testBrokerv2Message_whenSourceApplicationNonNil_andNonceMissingInResponse_shouldSucceed
{
    [ADBrokerKeyHelper setSymmetricKey:@"BU-bLN3zTfHmyhJ325A8dJJ1tzrnKMHEfsTlStdMo0U"];
    
    NSString* v2Base64UrlEncryptedPayload = @"TKQ6mTbSf_FgBnb5mvtnSQXQ4_LajVjSNPjymF1wI2ZQWzGSvut3mWziWV0Xvti_ULCFD39BwuFJykXxrtsHZeuynfHRdpUXnhm4qZoAiRfjgY37HBbYbXW3FLzQWvUTCBFz3S9MWpPQE1bJmgke8NisoZ7jlj_gJh-nkfL_Kqg_q7f-AGHvF_TKZoZajosKjbSXzSrW5jLVEA8evIezJS_mIAIUTxxtyoDr1XnQmL2obbi2xLsdbfUDQYpRM2fVLQchO3P_J0TlJrTlR7NAuGnjRUckQHXRsR0-qSK0zF_4rxlClrQgJOudWKpZCVVeUhHMNYzhehLNfABphLeAc_Vxbo7yf0pgKo482ThT86Zb438eSqHivrB8f3VGSx8jRd6MusubxG6VAE5iaHC3xzDumwxAC95QNzv4CspKl5Q";
    
    NSString* hash = @"922B2C67F3F8BEA82A3E3F5DD3DC8D7EA0CB2FED159A324C610E4AE07634C022";
    NSDictionary* resumeDictionary = @{ @"redirect_uri" : @"ms-outlook://", @"broker_nonce" : @"nonce"  };
    [[NSUserDefaults standardUserDefaults] setObject:resumeDictionary forKey:kAdalResumeDictionaryKey];
    
    NSDictionary* brokerMessage =
    @{
      @"msg_protocol_ver" : @"2",
      @"response" : v2Base64UrlEncryptedPayload,
      @"hash" : hash,
      };
    
    NSString* brokerUrlStr = [NSString stringWithFormat:@"ms-outlook://?%@", [brokerMessage msidWWWFormURLEncode]];
    NSURL* brokerUrl = [NSURL URLWithString:brokerUrlStr];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"Broker v2 message."];
    [ADBrokerNotificationManager.sharedInstance enableNotifications:^(ADAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertNil(result.error);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         
         XCTAssertEqualObjects(result.tokenCacheItem.resource, @"myfakeresource");
         XCTAssertNil(result.tokenCacheItem.accessToken);
         XCTAssertEqualObjects(result.tokenCacheItem.refreshToken, @"MyFakeRefreshToken");
         XCTAssertEqualObjects(result.tokenCacheItem.accessTokenType, @"Bearer");
         
         [expectation fulfill];
     }];
    
    XCTAssertTrue([ADAuthenticationContext handleBrokerResponse:brokerUrl sourceApplication:ADAL_BROKER_APP_BUNDLE_ID]);
    [self waitForExpectationsWithTimeout:1.0 handler:nil];
    
    XCTAssertNil([[NSUserDefaults standardUserDefaults] objectForKey:kAdalResumeDictionaryKey]);
}

- (void)testBrokerv2Message_whenSourceApplicationNil_andNonceMatches_shouldSucceed
{
    [ADBrokerKeyHelper setSymmetricKey:@"BU-bLN3zTfHmyhJ325A8dJJ1tzrnKMHEfsTlStdMo0U"];
    
    NSString* v2Base64UrlEncryptedPayload = @"UzLzGP78R7Ju4-5-YS23X-vNtZjkK4t2H7wULLZAZTzthtxGE5gHI95IZOIY7j_iUNG3fv57RSY8S8AQqT7KxXsIZ0k9XPKwXBqiOJG3-wUDLFMipvrFHUL5jg4MotNSdVNxEVl1H8kIWqJeGItEgRjPuTzVJir_Imog8aVImhq-pOPcN36kfNV_Cv9k8cBuqWDbHa5w8H8iUXBnIrI4cgfvqaxuO-lRcitf4xT3iaOMGzDMU2F2KpCTL3Rkt_tyYmUv_tqIamFnawXcVLcVfMVu3Zk8JuRZ0wUQn_zzUUu8VOfstQ9cSqhYHX1EnAhgX788b79FjcMzoY9C6VQoepB_uz9PEqOvR88Wnzkd9y5ubGJ7vCN03vSMxqDymowBzPTTCgz_rhNsWehnylzcz-W7Sx2UAGvXxhPvK7ny7IwlkroBjPm-gine4157_NMT";
    
    NSString* hash = @"752D8C22D3B0FCD5296E381B489901C1AFECD42F2380C908BC07F356E5BE333B";
    NSDictionary* resumeDictionary = @{ @"redirect_uri" : @"ms-outlook://", @"broker_nonce" : @"nonce"  };
    [[NSUserDefaults standardUserDefaults] setObject:resumeDictionary forKey:kAdalResumeDictionaryKey];
    
    NSDictionary* brokerMessage =
    @{
      @"msg_protocol_ver" : @"2",
      @"response" : v2Base64UrlEncryptedPayload,
      @"hash" : hash,
      };
    
    NSString* brokerUrlStr = [NSString stringWithFormat:@"ms-outlook://?%@", [NSString msidWWWFormURLEncodedStringFromDictionary:brokerMessage]];
    NSURL* brokerUrl = [NSURL URLWithString:brokerUrlStr];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"Broker v2 message."];
    [ADBrokerNotificationManager.sharedInstance enableNotifications:^(ADAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertNil(result.error);
         XCTAssertEqual(result.status, AD_SUCCEEDED);
         
         XCTAssertEqualObjects(result.tokenCacheItem.resource, @"myfakeresource");
         XCTAssertNil(result.tokenCacheItem.accessToken);
         XCTAssertEqualObjects(result.tokenCacheItem.refreshToken, @"MyFakeRefreshToken");
         XCTAssertEqualObjects(result.tokenCacheItem.accessTokenType, @"Bearer");
         
         [expectation fulfill];
     }];
    
    XCTAssertTrue([ADAuthenticationContext handleBrokerResponse:brokerUrl sourceApplication:nil]);
    [self waitForExpectationsWithTimeout:1.0 handler:nil];
    
    XCTAssertNil([[NSUserDefaults standardUserDefaults] objectForKey:kAdalResumeDictionaryKey]);
}

- (void)testBrokerv2Message_whenSourceApplicationNil_andNonceMissingInResponse_shouleFailWithError
{
    [ADBrokerKeyHelper setSymmetricKey:@"BU-bLN3zTfHmyhJ325A8dJJ1tzrnKMHEfsTlStdMo0U"];
    
    NSString* v2Base64UrlEncryptedPayload = @"TKQ6mTbSf_FgBnb5mvtnSQXQ4_LajVjSNPjymF1wI2ZQWzGSvut3mWziWV0Xvti_ULCFD39BwuFJykXxrtsHZeuynfHRdpUXnhm4qZoAiRfjgY37HBbYbXW3FLzQWvUTCBFz3S9MWpPQE1bJmgke8NisoZ7jlj_gJh-nkfL_Kqg_q7f-AGHvF_TKZoZajosKjbSXzSrW5jLVEA8evIezJS_mIAIUTxxtyoDr1XnQmL2obbi2xLsdbfUDQYpRM2fVLQchO3P_J0TlJrTlR7NAuGnjRUckQHXRsR0-qSK0zF_4rxlClrQgJOudWKpZCVVeUhHMNYzhehLNfABphLeAc_Vxbo7yf0pgKo482ThT86Zb438eSqHivrB8f3VGSx8jRd6MusubxG6VAE5iaHC3xzDumwxAC95QNzv4CspKl5Q";
    
    NSString* hash = @"922B2C67F3F8BEA82A3E3F5DD3DC8D7EA0CB2FED159A324C610E4AE07634C022";
    NSDictionary* resumeDictionary = @{ @"redirect_uri" : @"ms-outlook://", @"broker_nonce" : @"nonce"  };
    [[NSUserDefaults standardUserDefaults] setObject:resumeDictionary forKey:kAdalResumeDictionaryKey];
    
    NSDictionary* brokerMessage =
    @{
      @"msg_protocol_ver" : @"2",
      @"response" : v2Base64UrlEncryptedPayload,
      @"hash" : hash,
      };
    
    NSString* brokerUrlStr = [NSString stringWithFormat:@"ms-outlook://?%@", [brokerMessage msidWWWFormURLEncode]];
    NSURL* brokerUrl = [NSURL URLWithString:brokerUrlStr];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"Broker v2 message."];
    [ADBrokerNotificationManager.sharedInstance enableNotifications:^(ADAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqualObjects(result.error.domain, ADAuthenticationErrorDomain);
         XCTAssertEqual(result.error.code, AD_ERROR_TOKENBROKER_MISMATCHED_RESUME_STATE);
         XCTAssertEqualObjects(result.error.errorDetails, @"Nonce in broker response does not match!");
         
         [expectation fulfill];
     }];
    
    XCTAssertFalse([ADAuthenticationContext handleBrokerResponse:brokerUrl sourceApplication:nil]);
    [self waitForExpectationsWithTimeout:1.0 handler:nil];
    
    XCTAssertNil([[NSUserDefaults standardUserDefaults] objectForKey:kAdalResumeDictionaryKey]);
}

- (void)testBrokerv2Message_whenSourceApplicationNil_andNonceMismatch_shouleFailWithError
{
    [ADBrokerKeyHelper setSymmetricKey:@"BU-bLN3zTfHmyhJ325A8dJJ1tzrnKMHEfsTlStdMo0U"];
    
    NSString* v2Base64UrlEncryptedPayload = @"UzLzGP78R7Ju4-5-YS23X-vNtZjkK4t2H7wULLZAZTzthtxGE5gHI95IZOIY7j_iUNG3fv57RSY8S8AQqT7KxXsIZ0k9XPKwXBqiOJG3-wUDLFMipvrFHUL5jg4MotNSdVNxEVl1H8kIWqJeGItEgRjPuTzVJir_Imog8aVImhq-pOPcN36kfNV_Cv9k8cBuqWDbHa5w8H8iUXBnIrI4cgfvqaxuO-lRcitf4xT3iaOMGzDMU2F2KpCTL3Rkt_tyYmUv_tqIamFnawXcVLcVfMVu3Zk8JuRZ0wUQn_zzUUu8VOfstQ9cSqhYHX1EnAhg0izUKghsfrHTkVksJ04bCU7ZZT-X0Ie6Fbbm3hDVF0WhjnY4DXyqOWbCb2RLmwaloHDT74PSDTEb0bIN_Vu2ALBvUvNJxr5VHjfilO_mxxNF6NY_rkuXDQciv3TZ2pqg";
    
    NSString* hash = @"6BBFBE5168CBFFD55CD6B4ED417733ED20CCD4C443D71C50A4E2D597C0C4E1C0";
    NSDictionary* resumeDictionary = @{ @"redirect_uri" : @"ms-outlook://", @"broker_nonce" : @"nonce"  };
    [[NSUserDefaults standardUserDefaults] setObject:resumeDictionary forKey:kAdalResumeDictionaryKey];
    
    NSDictionary* brokerMessage =
    @{
      @"msg_protocol_ver" : @"2",
      @"response" : v2Base64UrlEncryptedPayload,
      @"hash" : hash,
      };
    
    NSString* brokerUrlStr = [NSString stringWithFormat:@"ms-outlook://?%@", [brokerMessage msidWWWFormURLEncode]];
    NSURL* brokerUrl = [NSURL URLWithString:brokerUrlStr];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"Broker v2 message."];
    [ADBrokerNotificationManager.sharedInstance enableNotifications:^(ADAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqualObjects(result.error.domain, ADAuthenticationErrorDomain);
         XCTAssertEqual(result.error.code, AD_ERROR_TOKENBROKER_MISMATCHED_RESUME_STATE);
         XCTAssertEqualObjects(result.error.errorDetails, @"Nonce in broker response does not match!");
         
         [expectation fulfill];
     }];
    
    XCTAssertFalse([ADAuthenticationContext handleBrokerResponse:brokerUrl sourceApplication:nil]);
    [self waitForExpectationsWithTimeout:1.0 handler:nil];
    
    XCTAssertNil([[NSUserDefaults standardUserDefaults] objectForKey:kAdalResumeDictionaryKey]);
}

- (void)testBrokerErrorMessage_whenBrokerReturnsNoErrorDomain_shouldCreateErrorWithADAuthenticationErrorDomain
{
    NSDictionary *resumeDictionary = @{ @"redirect_uri" : @"ms-outlook://", @"broker_nonce" : @"nonce" };
    [[NSUserDefaults standardUserDefaults] setObject:resumeDictionary forKey:kAdalResumeDictionaryKey];
    
    NSDictionary *brokerMessage =
    @{
      @"code" : @"Interaction required.",
      @"correlation_id" : @"EC021F91-FAD9-41C6-A7B8-BD09D050E7C0",
      @"error_code" : @"202",
      @"error_description" : @"fake error description",
      @"x-broker-app-ver" : @"2.1.0",
      @"broker_nonce" : @"nonce"
      };
    
    NSString *brokerUrlStr = [NSString stringWithFormat:@"ms-outlook://?%@", [NSString msidWWWFormURLEncodedStringFromDictionary:brokerMessage]];
    NSURL *brokerUrl = [NSURL URLWithString:brokerUrlStr];
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"Broker no error domain."];
    [ADBrokerNotificationManager.sharedInstance enableNotifications:^(ADAuthenticationResult *result)
     {
         XCTAssertNotNil(result.error);
         XCTAssertEqualObjects(result.error.domain, ADAuthenticationErrorDomain);
         XCTAssertEqual(result.error.code, 202);
         XCTAssertEqualObjects(result.error.errorDetails, @"fake error description");
         XCTAssertEqualObjects(result.error.protocolCode, @"Interaction required.");
         
         [expectation fulfill];
     }];
    
    XCTAssertTrue([ADAuthenticationContext handleBrokerResponse:brokerUrl sourceApplication:ADAL_BROKER_APP_BUNDLE_ID]);
    [self waitForExpectationsWithTimeout:1.0 handler:nil];
    
    XCTAssertNil([[NSUserDefaults standardUserDefaults] objectForKey:kAdalResumeDictionaryKey]);
}

- (void)testBrokerErrorMessage_whenBrokerKeychainError_shouldCreateErrorWithKeychainErrorDomain
{
    NSDictionary *resumeDictionary = @{ @"redirect_uri" : @"ms-outlook://", @"broker_nonce" : @"nonce" };
    [[NSUserDefaults standardUserDefaults] setObject:resumeDictionary forKey:kAdalResumeDictionaryKey];

    NSDictionary *brokerMessage =
    @{
      @"code" : @"(null)",
      @"correlation_id" : @"EC021F91-FAD9-41C6-A7B8-BD09D050E7C0",
      @"error_code" : @"-25300",
      @"error_description" : @"Keychain failed during read operation",
      @"error_domain" : ADKeychainErrorDomain,
      @"x-broker-app-ver" : @"2.1.0",
      @"broker_nonce" : @"nonce"
      };

    NSString *brokerUrlStr = [NSString stringWithFormat:@"ms-outlook://?%@", [NSString msidWWWFormURLEncodedStringFromDictionary:brokerMessage]];
    NSURL *brokerUrl = [NSURL URLWithString:brokerUrlStr];

    XCTestExpectation *expectation = [self expectationWithDescription:@"Broker keychain error."];
    [ADBrokerNotificationManager.sharedInstance enableNotifications:^(ADAuthenticationResult *result)
     {
         XCTAssertNotNil(result.error);
         XCTAssertEqualObjects(result.error.domain, ADKeychainErrorDomain);
         XCTAssertEqual(result.error.code, -25300);
         XCTAssertEqualObjects(result.error.errorDetails, @"Keychain failed during read operation");
         XCTAssertEqualObjects(result.error.protocolCode, @"(null)");

         [expectation fulfill];
     }];

    XCTAssertTrue([ADAuthenticationContext handleBrokerResponse:brokerUrl sourceApplication:ADAL_BROKER_APP_BUNDLE_ID]);
    [self waitForExpectationsWithTimeout:1.0 handler:nil];

    XCTAssertNil([[NSUserDefaults standardUserDefaults] objectForKey:kAdalResumeDictionaryKey]);
}

- (void)testBrokerErrorMessage_whenBrokerHttpError_shouldCreateErrorWithHttpErrorDomain
{
    NSDictionary *resumeDictionary = @{ @"redirect_uri" : @"ms-outlook://", @"broker_nonce" : @"nonce" };
    [[NSUserDefaults standardUserDefaults] setObject:resumeDictionary forKey:kAdalResumeDictionaryKey];
    
    NSDictionary *brokerMessage =
    @{
      @"code" : @"(null)",
      @"correlation_id" : @"EC021F91-FAD9-41C6-A7B8-BD09D050E7C0",
      @"error_code" : @"429",
      @"error_description" : @"(3239 bytes)",
      @"error_domain" : ADHTTPErrorCodeDomain,
      @"http_headers" : @"Retry-After=120&Connection=Keep-alive&x-ms-clitelem=1%2C0%2C0%2C%2C",
      @"x-broker-app-ver" : @"2.1.0",
      @"broker_nonce" : @"nonce"
      };
    
    NSString *brokerUrlStr = [NSString stringWithFormat:@"ms-outlook://?%@", [NSString msidWWWFormURLEncodedStringFromDictionary:brokerMessage]];
    NSURL *brokerUrl = [NSURL URLWithString:brokerUrlStr];
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"Broker http error."];
    [ADBrokerNotificationManager.sharedInstance enableNotifications:^(ADAuthenticationResult *result)
     {
         XCTAssertNotNil(result.error);
         XCTAssertEqualObjects(result.error.domain, ADHTTPErrorCodeDomain);
         XCTAssertEqual(result.error.code, 429);
         XCTAssertEqualObjects(result.error.errorDetails, @"(3239 bytes)");
         XCTAssertEqualObjects(result.error.protocolCode, nil);
         XCTAssertEqualObjects(result.error.userInfo[ADHTTPHeadersKey][@"Retry-After"], @"120");
         
         [expectation fulfill];
     }];
    
    XCTAssertTrue([ADAuthenticationContext handleBrokerResponse:brokerUrl sourceApplication:ADAL_BROKER_APP_BUNDLE_ID]);
    [self waitForExpectationsWithTimeout:1.0 handler:nil];
    
    XCTAssertNil([[NSUserDefaults standardUserDefaults] objectForKey:kAdalResumeDictionaryKey]);
}

- (void)testBrokerErrorMessage_whenBrokerServerError_shouldCreateErrorWithServerErrorDomain
{
    NSDictionary *resumeDictionary = @{ @"redirect_uri" : @"ms-outlook://", @"broker_nonce" : @"nonce" };
    [[NSUserDefaults standardUserDefaults] setObject:resumeDictionary forKey:kAdalResumeDictionaryKey];
    
    NSDictionary *brokerMessage =
    @{
      @"code" : @"Refresh token is rejected due to inactivity.",
      @"correlation_id" : @"EC021F91-FAD9-41C6-A7B8-BD09D050E7C0",
      @"error_code" : @"202",
      @"error_description" : @"fake error description",
      @"error_domain" : ADOAuthServerErrorDomain,
      @"x-broker-app-ver" : @"2.1.0",
      @"broker_nonce" : @"nonce"
      };
    
    NSString *brokerUrlStr = [NSString stringWithFormat:@"ms-outlook://?%@", [brokerMessage msidWWWFormURLEncode]];
    NSURL *brokerUrl = [NSURL URLWithString:brokerUrlStr];
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"Broker keychain error."];
    [ADBrokerNotificationManager.sharedInstance enableNotifications:^(ADAuthenticationResult *result)
     {
         XCTAssertNotNil(result.error);
         XCTAssertEqualObjects(result.error.domain, ADOAuthServerErrorDomain);
         XCTAssertEqual(result.error.code, 202);
         XCTAssertEqualObjects(result.error.errorDetails, @"fake error description");
         XCTAssertEqualObjects(result.error.protocolCode, @"Refresh token is rejected due to inactivity.");
         
         [expectation fulfill];
     }];
    
    XCTAssertTrue([ADAuthenticationContext handleBrokerResponse:brokerUrl sourceApplication:ADAL_BROKER_APP_BUNDLE_ID]);
    [self waitForExpectationsWithTimeout:1.0 handler:nil];
    
    XCTAssertNil([[NSUserDefaults standardUserDefaults] objectForKey:kAdalResumeDictionaryKey]);
}

- (void)testBrokerErrorMessage_whenSourceApplicationNonNil_andNonceMissingInResponse_shouldParseError
{
    NSDictionary *resumeDictionary = @{ @"redirect_uri" : @"ms-outlook://", @"broker_nonce" : @"nonce" };
    [[NSUserDefaults standardUserDefaults] setObject:resumeDictionary forKey:kAdalResumeDictionaryKey];
    
    NSDictionary *brokerMessage =
    @{
      @"code" : @"Refresh token is rejected due to inactivity.",
      @"correlation_id" : @"EC021F91-FAD9-41C6-A7B8-BD09D050E7C0",
      @"error_code" : @"202",
      @"error_description" : @"fake error description",
      @"error_domain" : ADOAuthServerErrorDomain,
      @"x-broker-app-ver" : @"2.1.0",
      };
    
    NSString *brokerUrlStr = [NSString stringWithFormat:@"ms-outlook://?%@", [brokerMessage msidWWWFormURLEncode]];
    NSURL *brokerUrl = [NSURL URLWithString:brokerUrlStr];
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"Broker keychain error."];
    [ADBrokerNotificationManager.sharedInstance enableNotifications:^(ADAuthenticationResult *result)
     {
         XCTAssertNotNil(result.error);
         XCTAssertEqualObjects(result.error.domain, ADOAuthServerErrorDomain);
         XCTAssertEqual(result.error.code, 202);
         XCTAssertEqualObjects(result.error.errorDetails, @"fake error description");
         XCTAssertEqualObjects(result.error.protocolCode, @"Refresh token is rejected due to inactivity.");
         
         [expectation fulfill];
     }];
    
    XCTAssertTrue([ADAuthenticationContext handleBrokerResponse:brokerUrl sourceApplication:ADAL_BROKER_APP_BUNDLE_ID]);
    [self waitForExpectationsWithTimeout:1.0 handler:nil];
    
    XCTAssertNil([[NSUserDefaults standardUserDefaults] objectForKey:kAdalResumeDictionaryKey]);
}

- (void)testBrokerErrorMessage_whenSourceApplicationNil_andNonceMatch_shouldParseError
{
    NSDictionary *resumeDictionary = @{ @"redirect_uri" : @"ms-outlook://", @"broker_nonce" : @"nonce" };
    [[NSUserDefaults standardUserDefaults] setObject:resumeDictionary forKey:kAdalResumeDictionaryKey];
    
    NSDictionary *brokerMessage =
    @{
      @"code" : @"Refresh token is rejected due to inactivity.",
      @"correlation_id" : @"EC021F91-FAD9-41C6-A7B8-BD09D050E7C0",
      @"error_code" : @"202",
      @"error_description" : @"fake error description",
      @"error_domain" : ADOAuthServerErrorDomain,
      @"x-broker-app-ver" : @"2.1.0",
      @"broker_nonce" : @"nonce"
      };
    
    NSString *brokerUrlStr = [NSString stringWithFormat:@"ms-outlook://?%@", [NSString msidWWWFormURLEncodedStringFromDictionary:brokerMessage]];
    NSURL *brokerUrl = [NSURL URLWithString:brokerUrlStr];
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"Broker keychain error."];
    [ADBrokerNotificationManager.sharedInstance enableNotifications:^(ADAuthenticationResult *result)
     {
         XCTAssertNotNil(result.error);
         XCTAssertEqualObjects(result.error.domain, ADOAuthServerErrorDomain);
         XCTAssertEqual(result.error.code, 202);
         XCTAssertEqualObjects(result.error.errorDetails, @"fake error description");
         XCTAssertEqualObjects(result.error.protocolCode, @"Refresh token is rejected due to inactivity.");
         
         [expectation fulfill];
     }];
    
    XCTAssertTrue([ADAuthenticationContext handleBrokerResponse:brokerUrl sourceApplication:nil]);
    [self waitForExpectationsWithTimeout:1.0 handler:nil];
    
    XCTAssertNil([[NSUserDefaults standardUserDefaults] objectForKey:kAdalResumeDictionaryKey]);
}

- (void)testBrokerErrorMessage_whenSourceApplicationNil_andNonceMissingInResponse_shouldFailWithResumeStateMismatch
{
    NSDictionary *resumeDictionary = @{ @"redirect_uri" : @"ms-outlook://", @"broker_nonce" : @"nonce" };
    [[NSUserDefaults standardUserDefaults] setObject:resumeDictionary forKey:kAdalResumeDictionaryKey];
    
    NSDictionary *brokerMessage =
    @{
      @"code" : @"Refresh token is rejected due to inactivity.",
      @"correlation_id" : @"EC021F91-FAD9-41C6-A7B8-BD09D050E7C0",
      @"error_code" : @"202",
      @"error_description" : @"fake error description",
      @"error_domain" : ADOAuthServerErrorDomain,
      @"x-broker-app-ver" : @"2.1.0",
      };
    
    NSString *brokerUrlStr = [NSString stringWithFormat:@"ms-outlook://?%@", [brokerMessage msidWWWFormURLEncode]];
    NSURL *brokerUrl = [NSURL URLWithString:brokerUrlStr];
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"Broker keychain error."];
    [ADBrokerNotificationManager.sharedInstance enableNotifications:^(ADAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqualObjects(result.error.domain, ADAuthenticationErrorDomain);
         XCTAssertEqual(result.error.code, AD_ERROR_TOKENBROKER_MISMATCHED_RESUME_STATE);
         XCTAssertEqualObjects(result.error.errorDetails, @"Nonce in broker response does not match!");
         
         [expectation fulfill];
     }];
    
    XCTAssertFalse([ADAuthenticationContext handleBrokerResponse:brokerUrl sourceApplication:nil]);
    [self waitForExpectationsWithTimeout:1.0 handler:nil];
    
    XCTAssertNil([[NSUserDefaults standardUserDefaults] objectForKey:kAdalResumeDictionaryKey]);
}

- (void)testBrokerErrorMessage_whenSourceApplicationNil_andNonceMismatch_shouldFailWithResumeStateMismatch
{
    NSDictionary *resumeDictionary = @{ @"redirect_uri" : @"ms-outlook://", @"broker_nonce" : @"nonce" };
    [[NSUserDefaults standardUserDefaults] setObject:resumeDictionary forKey:kAdalResumeDictionaryKey];
    
    NSDictionary *brokerMessage =
    @{
      @"code" : @"Refresh token is rejected due to inactivity.",
      @"correlation_id" : @"EC021F91-FAD9-41C6-A7B8-BD09D050E7C0",
      @"error_code" : @"202",
      @"error_description" : @"fake error description",
      @"error_domain" : ADOAuthServerErrorDomain,
      @"x-broker-app-ver" : @"2.1.0",
      @"broker_nonce" : @"nonce2"
      };
    
    NSString *brokerUrlStr = [NSString stringWithFormat:@"ms-outlook://?%@", [brokerMessage msidWWWFormURLEncode]];
    NSURL *brokerUrl = [NSURL URLWithString:brokerUrlStr];
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"Broker keychain error."];
    [ADBrokerNotificationManager.sharedInstance enableNotifications:^(ADAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqualObjects(result.error.domain, ADAuthenticationErrorDomain);
         XCTAssertEqual(result.error.code, AD_ERROR_TOKENBROKER_MISMATCHED_RESUME_STATE);
         XCTAssertEqualObjects(result.error.errorDetails, @"Nonce in broker response does not match!");
         
         [expectation fulfill];
     }];
    
    XCTAssertFalse([ADAuthenticationContext handleBrokerResponse:brokerUrl sourceApplication:nil]);
    [self waitForExpectationsWithTimeout:1.0 handler:nil];
    
    XCTAssertNil([[NSUserDefaults standardUserDefaults] objectForKey:kAdalResumeDictionaryKey]);
}

@end
