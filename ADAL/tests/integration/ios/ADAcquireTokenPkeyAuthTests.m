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
#import "XCTestCase+TestHelperMethods.h"
#import "ADTokenCache+Internal.h"
#import "ADAuthenticationContext+Internal.h"
#import "ADTestURLSession.h"
#import "ADTokenCacheItem+Internal.h"
#import "NSDictionary+MSIDTestUtil.h"
#import "MSIDKeychainTokenCache+MSIDTestsUtil.h"
#import "ADLegacyKeychainTokenCache.h"

@interface ADAcquireTokenPkeyAuthTests : ADTestCase

@end

@implementation ADAcquireTokenPkeyAuthTests

- (void)setUp
{
    [super setUp];
    
    [MSIDKeychainTokenCache reset];
}

- (void)tearDown
{
    [super tearDown];
    
    [MSIDKeychainTokenCache reset];
}

#pragma mark - Tests

- (void)testTokenEndpointPkeyAuthNoWPJ
{
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    
    // Add an MRRT to the cache
    [ADLegacyKeychainTokenCache.defaultKeychainCache addOrUpdateItem:[self adCreateMRRTCacheItem] correlationId:nil error:&error];
    XCTAssertNil(error);
    
    [ADTestURLSession addResponses:@[[ADTestAuthorityValidationResponse invalidAuthority:TEST_AUTHORITY trustedHost:@"login.windows.net"],
                                     [self defaultTokenEndpointPkeyAuthChallenge],
                                     [self defaultPkeyAuthNoWPJResponse]]];
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilent should return new token."];
    
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
         
         [expectation fulfill];
     }];
    
    [self waitForExpectations:@[expectation] timeout:1];
    
    NSArray* allItems = [ADLegacyKeychainTokenCache.defaultKeychainCache allItems:&error];
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

#pragma mark - Private

- (ADAuthenticationContext *)getTestAuthenticationContext
{
    ADAuthenticationContext* context =
    [[ADAuthenticationContext alloc] initWithAuthority:TEST_AUTHORITY
                                     validateAuthority:NO
                                                 error:nil];
    
    NSAssert(context, @"If this is failing for whatever reason you should probably fix it before trying to run tests.");
    [context setCorrelationId:TEST_CORRELATION_ID];
    
    return context;
}


- (ADTestURLResponse *)defaultTokenEndpointPkeyAuthChallenge
{
    return [self adDefaultRefreshReponseCode:401
                             responseHeaders:@{ @"WWW-Authenticate" : @"PKeyAuth nonce=\"AAABAAEAiL9Kn2Z27UubvWFPbm0gLdtsn-PXocm89MSCN-jy-PyMb1txkhQMWoFNUDgLkmMs1OnKIexU4jwre7oqMSKjpKk3wjvHvJlE6ZFBdeEKVQtd_IXHzbR9wT-obZUI5kM779akwJHoPQ4aBnGlrbqUTCAA\", CertAuthorities=\"OU=82dbaca4-3e81-46ca-9c73-0950c1eaca97,CN=MS-Organization-Access,DC=windows,DC=net\", Version=\"1.0\", Context=\"pkeyauth_context\"" }
                                responseJson:nil];
}

- (ADTestURLResponse *)defaultPkeyAuthNoWPJResponse
{
    NSString* expectedAuthHeader = @"PKeyAuth  Context=\"pkeyauth_context\", Version=\"1.0\"";
    return [self adResponseRefreshToken:TEST_REFRESH_TOKEN
                              authority:TEST_AUTHORITY
                               resource:TEST_RESOURCE
                               clientId:TEST_CLIENT_ID
                         requestHeaders:@{ @"Authorization" : expectedAuthHeader }
                          correlationId:TEST_CORRELATION_ID
                        newRefreshToken:@"new refresh token"
                         newAccessToken:@"new access token"
                             newIDToken:[self adDefaultIDToken]
                       additionalFields:nil];
}

@end
