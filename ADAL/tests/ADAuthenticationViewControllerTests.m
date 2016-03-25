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

@interface ADAuthenticationViewControllerTests : XCTestCase
{
@private
    dispatch_semaphore_t _dsem;
}

@end

@implementation ADAuthenticationViewControllerTests

- (void)setUp
{
    [super setUp];
    _dsem = dispatch_semaphore_create(0);
}

- (void)tearDown
{
    SAFE_ARC_DISPATCH_RELEASE(_dsem);
    _dsem = nil;
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

- (void)testNonHttpsRedirectInWebView
{
    //Create a context with empty token cache
    ADAuthenticationContext* context = [self getTestAuthenticationContext];
    
    //Add two delegate calls to the mocking ADTestAuthenticationViewController
    //First one in https while the second one in http
    [ADTestAuthenticationViewController addDelegateCallWebAuthShouldStartLoadRequest:[NSURLRequest requestWithURL:[NSURL URLWithString:TEST_AUTHORITY]]];
    [ADTestAuthenticationViewController addDelegateCallWebAuthShouldStartLoadRequest:[NSURLRequest requestWithURL:[NSURL URLWithString:@"http://abc.com"]]];
    
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                               userId:TEST_USER_ID
                      completionBlock:^(ADAuthenticationResult *result)
     {
         //Should fail with AD_ERROR_NON_HTTPS_REDIRECT error
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_SERVER_NON_HTTPS_REDIRECT);
         
         dispatch_semaphore_signal(_dsem);
     }];
    
    [self waitSemaphoreWithoutBlockingMainQueue:_dsem];
    
}

- (void)waitSemaphoreWithoutBlockingMainQueue:(dispatch_semaphore_t)sem
{
    while (dispatch_semaphore_wait(sem, DISPATCH_TIME_NOW))
    {
        [[NSRunLoop mainRunLoop] runMode:NSDefaultRunLoopMode beforeDate: [NSDate distantFuture]];
    }
}

@end