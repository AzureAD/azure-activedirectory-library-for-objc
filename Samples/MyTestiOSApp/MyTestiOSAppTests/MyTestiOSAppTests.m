// Created by Boris Vidolov on 9/13/13.
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
#import <ADALiOS/ADAuthenticationContext.h>
#import "BVTestAppDelegate.h"
#import <ADAliOS/ADAuthenticationSettings.h>

@interface MyTestiOSAppTests : XCTestCase
{
    NSString* mAuthority;
    NSString* mClientId;
    NSString* mResource;
    NSString* mRedirectUri;
    NSString* mUserId;
    ADAuthenticationContext* mContext;
}

@end

@implementation MyTestiOSAppTests

- (void)setUp
{
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
    // The values below use a sample Azure Active Directory tenant and a sample user there:
    mAuthority = @"https://login.windows.net/msopentechbv.onmicrosoft.com";
    mClientId = @"c3c7f5e5-7153-44d4-90e6-329686d48d76";
    mResource = @"http://localhost/TodoListService";
    mRedirectUri = @"http://todolistclient/";
    mUserId = @"boris@msopentechbv.onmicrosoft.com";
    
    ADAuthenticationError* error;
    mContext = [ADAuthenticationContext authenticationContextWithAuthority:mAuthority error:&error];
    XCTAssertNotNil(mContext);
    XCTAssertNil(error);
    
    //Start clean:
    [self deleteCookies];
    [mContext.tokenCacheStore removeAll];//Clear the cache
}

- (void)tearDown
{
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    mContext = nil;//Free the memory
    [super tearDown];
}

//Attempts to find an active webview among all of the application windows.
//The method is not very efficient, but is robust and should suffice for the
//relatively small test app.
-(UIWebView*) findWebView: (UIWindow*) parent
{
    NSArray* windows = (parent) ? [parent subviews] : [[UIApplication sharedApplication] windows];
    for(UIWindow* window in windows)
    {
        if ([window isKindOfClass:[UIWebView class]])
        {
            return (UIWebView*)window;
        }
        else
        {
            UIWebView* result = [self findWebView:window];
            if (result)
                return result;
        }
    }
    return nil;
}

//Clears all cookies:
-(void) deleteCookies
{
    NSHTTPCookieStorage* cookiesStorage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    NSMutableArray* allCookies = [NSMutableArray arrayWithArray:cookiesStorage.cookies];
    for(NSHTTPCookie* cookie in allCookies)
    {
        [cookiesStorage deleteCookie:cookie];
    }
}

//Runs the run loop in the current thread until the passed condition
//turns YES or timeout is reached
-(void) runLoopWithTimeOut: (int) timeOutSeconds
                 operation: (NSString*) operationDescription
                      line: (int) sourceLine
                 condition: (BOOL (^)(void)) condition
{
    BOOL succeeded = NO;
    NSDate* timeOut = [NSDate dateWithTimeIntervalSinceNow:timeOutSeconds];//In seconds
    NSRunLoop* mainLoop = [NSRunLoop mainRunLoop];
    XCTAssertNotNil(mainLoop);
    
    while ([[NSDate dateWithTimeIntervalSinceNow:0] compare:timeOut] != NSOrderedDescending)
    {
        [mainLoop runMode:NSDefaultRunLoopMode beforeDate:timeOut];//Process one event
        if (condition())
        {
            succeeded = YES;
            break;
        }
    }
    if (!succeeded)
    {
        NSString* error = [NSString stringWithFormat:@"Timeout: %@", operationDescription];
        [self recordFailureWithDescription:error inFile:@"" __FILE__ atLine:sourceLine expected:NO];
    }
}

//Calls the asynchronous acquireTokenWithResource method.
//"interactive" parameter indicates whether the call will display
//UI which user will interact with
-(ADAuthenticationResult*) callAcquireToken: (BOOL) interactive
                               keepSignedIn: (BOOL) keepSignedIn
                                       line: (int) sourceLine
{
    __block ADAuthenticationResult* localResult;
    [mContext acquireTokenWithResource:mResource
                              clientId:mClientId
                           redirectUri:[NSURL URLWithString:mRedirectUri]
                                userId:mUserId
                       completionBlock:^(ADAuthenticationResult *result)
     {
         localResult = result;
     }];
   
    if (interactive)
    {
        //Automated the webview:
        __block UIWebView* webView;
        [self runLoopWithTimeOut:5 operation:@"Wait for web view" line:sourceLine condition:^{
            webView = [self findWebView:nil];
            return (BOOL)(webView != nil);
        }];
        if (!webView)
        {
            return nil;
        }
        
        [self runLoopWithTimeOut:5 operation:@"Wait for the login page" line:sourceLine condition:^{
            if (webView.loading)
            {
                return NO;
            }
            //webview loaded, check if the credentials form is there, else we are still
            //in the initial redirect stages:
            NSString* formLoaded = [webView stringByEvaluatingJavaScriptFromString:
                                    @"document.forms['credentials'] ? '1' : '0'"];
            return [formLoaded isEqualToString:@"1"];
        }];
        
        //Check the username:
        NSString* formUserId = [webView stringByEvaluatingJavaScriptFromString:
                                @"document.getElementById('cred_userid_inputtext').value"];
        XCTAssertTrue([formUserId isEqualToString:mUserId]);
        
        //Add the password:
        [webView stringByEvaluatingJavaScriptFromString:
                @"document.getElementById('cred_password_inputtext').value = '~test123'"];
        if (keepSignedIn)
        {
            [webView stringByEvaluatingJavaScriptFromString:
                @"document.getElementById('cred_keep_me_signed_in_checkbox').checked = true"];
        }
        //Submit:
        [webView stringByEvaluatingJavaScriptFromString:
               @"document.forms['credentials'].submit()"];
    
    }
    
    [self runLoopWithTimeOut:30 operation:@"Wait for the post-webview calls" line:sourceLine condition:^{
        return (BOOL)(!!localResult);
    }];

    if (AD_SUCCEEDED != localResult.status || localResult.error)
    {
        [self recordFailureWithDescription:localResult.error.errorDetails
                                    inFile:@"" __FILE__
                                    atLine:sourceLine
                                  expected:NO];
    }
    
    if ([NSString isStringNilOrBlank:localResult.tokenCacheStoreItem.accessToken])
    {
        [self recordFailureWithDescription:@"Nil or empty access token."
                                    inFile:@"" __FILE__
                                    atLine:sourceLine
                                  expected:NO];
    }
    
    return localResult;
}

- (void)testInitialAcquireToken
{
    [self callAcquireToken:YES keepSignedIn:NO line:__LINE__];
}

-(void) testCache
{
    [self callAcquireToken:YES keepSignedIn:NO line:__LINE__];
    
    //Now ensure that the cache is used:
    [self deleteCookies];//No cookies, force cache use:
    ADAuthenticationResult* result = [self callAcquireToken:NO keepSignedIn:YES line:__LINE__];
    
    //Now remove the access token and ensure that the refresh token is leveraged:
    result.tokenCacheStoreItem.accessToken = nil;
    ADAuthenticationError* error;
    [mContext.tokenCacheStore addOrUpdateItem:result.tokenCacheStoreItem error:&error];
    XCTAssertNil(error);
    [self callAcquireToken:NO keepSignedIn:YES line:__LINE__];
}

//TODO: Enable this test. The issue is that the automation
//fails to set the persistent cookies. The issue cannot be reproduced
//outside of the UI automation tests.
//-(void) testCookies
//{
//    [self callAcquireToken:YES keepSignedIn:YES line:__LINE__];
//    
//    //Clear the cache, so that cookies are used:
//    [mContext.tokenCacheStore removeAll];
//    [self callAcquireToken:NO keepSignedIn:YES line:__LINE__];
//}
//
//
@end
