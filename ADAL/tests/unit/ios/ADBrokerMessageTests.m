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
#import "NSDictionary+ADExtensions.h"
#import "ADPkeyAuthHelper.h"
#import "XCTestCase+TestHelperMethods.h"
#import "ADUserInformation.h"
#import "ADTokenCacheItem.h"

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

- (void)testNonBrokerResponse
{
    // Set a redirect in the resume dictionary to make sure we at least try to process this message
    NSDictionary* resumeDictionary = @{ @"redirect_uri" : @"ms-outlook://" };
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
    XCTAssertFalse([ADAuthenticationContext handleBrokerResponse:[NSURL URLWithString:@"ms-outlook://settings/help/intunediagnostics?source=authenticator"]]);
    
    [self waitForExpectationsWithTimeout:1.0 handler:nil];
}

- (void)testNonBrokerResponseMismatchedRedirectUri
{
    // Set a redirect in the resume dictionary to make sure we at least try to process this message
    NSDictionary* resumeDictionary = @{ @"redirect_uri" : @"different-redirect-uri://" };
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
    XCTAssertFalse([ADAuthenticationContext handleBrokerResponse:[NSURL URLWithString:@"ms-outlook://settings/help/intunediagnostics?source=authenticator"]]);
    
    [self waitForExpectationsWithTimeout:1.0 handler:nil];
}

- (void)testBrokerv2Message
{
    [ADBrokerKeyHelper setSymmetricKey:@"BU-bLN3zTfHmyhJ325A8dJJ1tzrnKMHEfsTlStdMo0U"];
    
    NSString* v2Base64UrlEncryptedPayload = @"TKQ6mTbSf_FgBnb5mvtnSQXQ4_LajVjSNPjymF1wI2ZQWzGSvut3mWziWV0Xvti_ULCFD39BwuFJykXxrtsHZeuynfHRdpUXnhm4qZoAiRfjgY37HBbYbXW3FLzQWvUTCBFz3S9MWpPQE1bJmgke8NisoZ7jlj_gJh-nkfL_Kqg_q7f-AGHvF_TKZoZajosKjbSXzSrW5jLVEA8evIezJS_mIAIUTxxtyoDr1XnQmL2obbi2xLsdbfUDQYpRM2fVLQchO3P_J0TlJrTlR7NAuGnjRUckQHXRsR0-qSK0zF_4rxlClrQgJOudWKpZCVVeUhHMNYzhehLNfABphLeAc_Vxbo7yf0pgKo482ThT86Zb438eSqHivrB8f3VGSx8jRd6MusubxG6VAE5iaHC3xzDumwxAC95QNzv4CspKl5Q";
     
    NSString* hash = @"922B2C67F3F8BEA82A3E3F5DD3DC8D7EA0CB2FED159A324C610E4AE07634C022";
    NSDictionary* resumeDictionary = @{ @"redirect_uri" : @"ms-outlook://" };
    [[NSUserDefaults standardUserDefaults] setObject:resumeDictionary forKey:kAdalResumeDictionaryKey];
    
    NSDictionary* brokerMessage =
    @{
      @"msg_protocol_ver" : @"2",
      @"response" : v2Base64UrlEncryptedPayload,
      @"hash" : hash,
      };
    
    NSString* brokerUrlStr = [NSString stringWithFormat:@"ms-outlook://?%@", [brokerMessage adURLFormEncode]];
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
    
    XCTAssertTrue([ADAuthenticationContext handleBrokerResponse:brokerUrl]);
    [self waitForExpectationsWithTimeout:1.0 handler:nil];
    
    XCTAssertNil([[NSUserDefaults standardUserDefaults] objectForKey:kAdalResumeDictionaryKey]);
}


@end
