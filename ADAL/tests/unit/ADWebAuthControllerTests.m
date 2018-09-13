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
#import "ADTestAuthenticationViewController.h"
#import "ADAuthenticationContext.h"
#import "ADAuthenticationContext+Internal.h"
#import "XCTestCase+TestHelperMethods.h"
#import "ADTokenCache+Internal.h"
#import "ADWebAuthController+Internal.h"
#import "ADAuthenticationContext+TestUtil.h"
#import "MSIDLegacyTokenCacheAccessor.h"

@interface ADWebAuthControllerTests : ADTestCase

@end

@implementation ADWebAuthControllerTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [ADTestAuthenticationViewController clearDelegateCalls];
    
    [super tearDown];
}

- (ADAuthenticationContext *)getTestAuthenticationContext
{
    ADAuthenticationContext* context =
    [[ADAuthenticationContext alloc] initWithAuthority:TEST_AUTHORITY
                                     validateAuthority:NO
                                                 error:nil];
    
    NSAssert(context, @"If this is failing for whatever reason you should probably fix it before trying to run tests.");
    context.tokenCache = [MSIDLegacyTokenCacheAccessor new];
    [context setCorrelationId:TEST_CORRELATION_ID];
    
    return context;
}

- (void)testAboutBlankWhitelistInWebView
{
    ADWebAuthController* controller = [ADWebAuthController sharedInstance];
    
    //add about:blank url in the middle to test that it does not fail as non-https redirect.
    [ADTestAuthenticationViewController addDelegateCallWebAuthShouldStartLoadRequest:[NSURLRequest requestWithURL:[NSURL URLWithString:TEST_AUTHORITY]]];
    [ADTestAuthenticationViewController addDelegateCallWebAuthShouldStartLoadRequest:[NSURLRequest requestWithURL:[NSURL URLWithString:@"about:blank"]]];
    [ADTestAuthenticationViewController addDelegateCallWebAuthShouldStartLoadRequest:[NSURLRequest requestWithURL:TEST_REDIRECT_URL]];

    ADRequestParameters* requestParams = [ADRequestParameters new];
    [requestParams setCorrelationId:[NSUUID new]];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"Load a page that redirects to about:blank."];
    
    [controller start:[NSURL URLWithString:TEST_AUTHORITY]
                  end:TEST_REDIRECT_URL
          refreshCred:nil
#if TARGET_OS_IPHONE
               parent:nil
           fullScreen:false
#endif
              webView:nil
              context:requestParams
           completion:^(ADAuthenticationError *error, NSURL *url) {
               
               XCTAssertNil(error);
               XCTAssertNotNil(url);
               XCTAssertEqual(url.absoluteString, TEST_REDIRECT_URL.absoluteString);
               [expectation fulfill];
    }];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];;
}

- (void)testNonHttpsRedirectInWebView
{
    ADWebAuthController* controller = [ADWebAuthController sharedInstance];
    
    //Add two delegate calls to the mocking ADTestAuthenticationViewController
    //First one in https while the second one in http
    [ADTestAuthenticationViewController addDelegateCallWebAuthShouldStartLoadRequest:[NSURLRequest requestWithURL:[NSURL URLWithString:TEST_AUTHORITY]]];
    [ADTestAuthenticationViewController addDelegateCallWebAuthShouldStartLoadRequest:[NSURLRequest requestWithURL:[NSURL URLWithString:@"http://abc.com"]]];
    
    ADRequestParameters* requestParams = [ADRequestParameters new];
    [requestParams setCorrelationId:[NSUUID new]];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"Load a page that redirects to not https url."];
    
    [controller start:[NSURL URLWithString:TEST_AUTHORITY]
                  end:TEST_REDIRECT_URL
          refreshCred:nil
#if TARGET_OS_IPHONE
               parent:nil
           fullScreen:false
#endif
              webView:nil
              context:requestParams
           completion:^(ADAuthenticationError *error, NSURL *url) {
               
               //Should fail with AD_ERROR_NON_HTTPS_REDIRECT error
               XCTAssertNil(url);
               XCTAssertNotNil(error);
               XCTAssertEqual(error.code, AD_ERROR_SERVER_NON_HTTPS_REDIRECT);
               
               [expectation fulfill];
           }];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
}

@end

