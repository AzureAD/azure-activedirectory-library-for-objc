// Copyright © Microsoft Open Technologies, Inc.
//
// All Rights Reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
// ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
// PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
//
// See the Apache License, Version 2.0 for the specific language
// governing permissions and limitations under the License.

#import <XCTest/XCTest.h>
#import "ADAL_Internal.h"
#import "ADTestAuthenticationViewController.h"
#import "ADAuthenticationContext.h"
#import "ADAuthenticationContext+Internal.h"
#import "XCTestCase+TestHelperMethods.h"
#import "ADTokenCache+Internal.h"
#import "ADWebAuthController+Internal.h"

@interface ADWebAuthControllerTests : XCTestCase

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
    ADTokenCache *tokenCache = [ADTokenCache new];
    [context setTokenCacheStore:tokenCache];
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
