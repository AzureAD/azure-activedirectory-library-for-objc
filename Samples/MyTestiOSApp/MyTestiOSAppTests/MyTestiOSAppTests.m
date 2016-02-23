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
#import <ADALiOS/ADAuthenticationContext.h>
#import "ADTestAppDelegate.h"
#import <ADAliOS/ADAuthenticationSettings.h>
#import <ADALiOS/ADLogger.h>
#import "ADTestInstance.h"
#import "ADTestAppSettings.h"
#import <ADALiOS/ADErrorCodes.h>

//Timeouts in seconds. They are inflated to accumulate cloud-based
//builds on slow VMs:

//May include authority validation:
const int sWebViewDisplayTimeout    = 20;
//The time from loading the webview through multiple redirects until the login page is displayed:
const int sLoginPageDisplayTimeout  = 30;
//Calling the token endpoint and processing the response to extract the token:
const int sTokenWorkflowTimeout     = 20;

@interface MyTestiOSAppTests : XCTestCase
{
    ADTestAppSettings* mTestSettings;
}

@end

@implementation MyTestiOSAppTests

-(ADAuthenticationContext*) createContextWithInstance: (ADTestInstance*) instance
                                                 line: (int) line;
{
    XCTAssertNotNil(instance, "Test error");
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context =
        [ADAuthenticationContext authenticationContextWithAuthority:instance.authority
                                                  validateAuthority:instance.validateAuthority
                                                              error:&error];
    if (!context || error)
    {
        [self recordFailureWithDescription:error.errorDetails inFile:@"" __FILE__ atLine:line expected:NO];
    }
    return context;
}

-(void) flushCodeCoverage
{
    [mTestSettings flushCodeCoverage];
}

//Obtains a test AAD instance and credentials:
-(ADTestInstance*) getAADInstance
{
    return mTestSettings.testAuthorities[sAADTestInstance];
}

- (void)setUp
{
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class:
    
    [ADLogger setLevel:ADAL_LOG_LEVEL_ERROR];//Meaningful log size
    
    //Start clean:
    [self clearCookies];
    [self clearCache];
    
    //Load test data:
    mTestSettings = [ADTestAppSettings new];
}

- (void)tearDown
{
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [self flushCodeCoverage];
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
            {
                return result;
            }
        }
    }
    return nil;
}

//Clears all cookies:
-(void) clearCookies
{
    NSHTTPCookieStorage* cookiesStorage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    NSMutableArray* allCookies = [NSMutableArray arrayWithArray:cookiesStorage.cookies];
    for(NSHTTPCookie* cookie in allCookies)
    {
        [cookiesStorage deleteCookie:cookie];
    }
}

-(void) clearCache
{
    ADAuthenticationError* error = nil;
    [[ADAuthenticationSettings sharedInstance].defaultTokenCacheStore removeAllWithError:&error];
    XCTAssertNil(error.errorDetails);
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

-(ADAuthenticationResult*) callAcquireTokenWithInstance: (ADTestInstance*) instance
                                        refresh_session: (BOOL) refresh_session
                                            interactive: (BOOL) interactive
                                           keepSignedIn: (BOOL) keepSignedIn
                                          expectSuccess: (BOOL) expectSuccess
                                                   line: (int) sourceLine
{
    return [self callAcquireTokenWithInstance:instance
                              refresh_session:refresh_session
                                  interactive:interactive
                                 keepSignedIn:keepSignedIn
                                expectSuccess:expectSuccess
                                       userId:instance.userId
                                         line:sourceLine];
}

-(void) setElementWithWebView: (UIWebView*) webView
                      element: (NSString*) elementName
                        value: (NSString*) value
{
    [webView stringByEvaluatingJavaScriptFromString:
     [NSString stringWithFormat:@"document.getElementById('%@').value = '%@'",
      elementName, value]];
}

-(NSString*) getElementWithWebView: (UIWebView*) webView
                           element: (NSString*) elementName
{
    return [webView stringByEvaluatingJavaScriptFromString:
            [NSString stringWithFormat:@"document.getElementById('%@').value", elementName]];
}

//Calls the asynchronous acquireTokenWithResource method.
//"interactive" parameter indicates whether the call will display
//UI which user will interact with
-(ADAuthenticationResult*) callAcquireTokenWithInstance: (ADTestInstance*) instance
                                        refresh_session: (BOOL) refresh_session
                                            interactive: (BOOL) interactive
                                           keepSignedIn: (BOOL) keepSignedIn
                                          expectSuccess: (BOOL) expectSuccess
                                                 userId: (ADUserIdentifier*)userId /*requested userid, may be different from entered*/
                                                   line: (int) sourceLine
{
    XCTAssertNotNil(instance, "Internal test failure.");
    
    __block ADAuthenticationResult* localResult;
    ADAuthenticationContext* context = [self createContextWithInstance:instance line:sourceLine];
    NSUUID* correlationId = [NSUUID UUID];
    context.correlationId = correlationId;
    [context acquireTokenWithResource:instance.resource
                             clientId:instance.clientId
                          redirectUri:[NSURL URLWithString:instance.redirectUri]
                       promptBehavior:refresh_session ? AD_PROMPT_REFRESH_SESSION : AD_PROMPT_AUTO
                               userId:userId
                 extraQueryParameters:instance.extraQueryParameters
                      completionBlock:^(ADAuthenticationResult *result)
     {
         localResult = result;
     }];
   
    if (interactive)
    {
        //Automated the webview:
        __block UIWebView* webView;
        [self runLoopWithTimeOut:sWebViewDisplayTimeout operation:@"Wait for web view" line:sourceLine condition:^{
            webView = [self findWebView:nil];
            return (BOOL)(webView != nil);
        }];
        if (!webView)
        {
            return nil;
        }
        
        [self runLoopWithTimeOut:sLoginPageDisplayTimeout operation:@"Wait for the login page" line:sourceLine condition:^{
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
        
        //Check the username is prepopulated to requested:
        NSString* formUserId = [self getElementWithWebView:webView element:@"cred_userid_inputtext"];
        XCTAssertTrue([formUserId isEqualToString:userId]);
        
        //Now set the userId to the one passed in the instance (may be different):
        [self setElementWithWebView:webView element:@"cred_userid_inputtext" value:instance.userId];
        
        //Add the password:
        [self setElementWithWebView:webView element:@"cred_password_inputtext" value:instance.password];
        if (keepSignedIn)
        {
            [webView stringByEvaluatingJavaScriptFromString:
                @"document.getElementById('cred_keep_me_signed_in_checkbox').checked = true"];
        }
        //Submit:
        [webView stringByEvaluatingJavaScriptFromString:
               @"document.forms['credentials'].submit()"];
    
    }
    
    [self runLoopWithTimeOut:sTokenWorkflowTimeout operation:@"Wait for the post-webview calls" line:sourceLine condition:^{
        return (BOOL)(!!localResult);
    }];

    if (AD_SUCCEEDED != localResult.status || localResult.error)
    {
        if (expectSuccess)
        {
            [self recordFailureWithDescription:localResult.error.errorDetails
                                        inFile:@"" __FILE__
                                        atLine:sourceLine
                                      expected:NO];
        }
    }
    else
    {
        if (!expectSuccess)
        {
            [self recordFailureWithDescription:@"acquireTokenWithResource did not fail."
                                        inFile:@"" __FILE__
                                        atLine:sourceLine
                                      expected:NO];
        }
        if (!localResult.tokenCacheItem.accessToken.length)
        {
            [self recordFailureWithDescription:@"Nil or empty access token."
                                        inFile:@"" __FILE__
                                        atLine:sourceLine
                                      expected:NO];
        }
    }
    
    return localResult;
}

- (void)testInitialAcquireToken
{
    ADTestInstance* instance = [self getAADInstance];
    [self callAcquireTokenWithInstance:instance
                       refresh_session:NO
                           interactive:YES
                          keepSignedIn:NO
                         expectSuccess:YES
                                  line:__LINE__];
    
    //Force authorization for the next calls:
    [self clearCache];
    [self clearCookies];
    //Add query parameters:
    instance.extraQueryParameters = @"&foo=bar&bar=foo";//With "&"
    [self callAcquireTokenWithInstance:instance
                       refresh_session:NO
                           interactive:YES
                          keepSignedIn:NO
                         expectSuccess:YES
                                  line:__LINE__];

    [self clearCache];
    [self clearCookies];
    instance.extraQueryParameters = @"foo=bar&bar=foo";//Without "&"
    [self callAcquireTokenWithInstance:instance
                       refresh_session:NO
                           interactive:YES
                          keepSignedIn:NO
                         expectSuccess:YES
                                  line:__LINE__];}

-(void) testCache
{
    ADTestInstance* instance = [self getAADInstance];
    [self callAcquireTokenWithInstance:instance
                       refresh_session:NO
                           interactive:YES
                          keepSignedIn:NO
                         expectSuccess:YES
                                  line:__LINE__];
    
    //Now ensure that the cache is used:
    [self clearCookies];//No cookies, force cache use:
    ADAuthenticationResult* result = [self callAcquireTokenWithInstance:instance
                                                        refresh_session:NO
                                                            interactive:NO
                                                           keepSignedIn:YES
                                                          expectSuccess:YES
                                                                   line:__LINE__];
    
    //Now remove the access token and ensure that the refresh token is leveraged:
    result.tokenCacheItem.accessToken = nil;
    ADAuthenticationError* error = nil;
    [[ADAuthenticationSettings sharedInstance].defaultTokenCacheStore addOrUpdateItem:result.tokenCacheItem error:&error];
    XCTAssertNil(error);
    [self clearCookies];//Just in case
    [self callAcquireTokenWithInstance:instance
                       refresh_session:NO
                           interactive:NO
                          keepSignedIn:YES
                         expectSuccess:YES
                                  line:__LINE__];
}

-(void) testCookies
{
    ADTestInstance* instance = [self getAADInstance];
    [self callAcquireTokenWithInstance:instance
                       refresh_session:NO
                           interactive:YES
                          keepSignedIn:YES
                         expectSuccess:YES
                                  line:__LINE__];
    
    //Clear the cache, so that cookies are used:
    [self clearCache];
    [self callAcquireTokenWithInstance:instance
                       refresh_session:NO
                           interactive:NO
                          keepSignedIn:YES
                         expectSuccess:YES
                                  line:__LINE__];
}

-(void) testNegative
{
    //Bad SSL certificate:
    ADTestInstance* instance = [self getAADInstance];
    instance.authority = @"https://example.com/common";
    instance.validateAuthority = NO;
    ADAuthenticationResult* result = [self callAcquireTokenWithInstance:instance
                                                        refresh_session:NO
                                                            interactive:NO
                                                           keepSignedIn:YES
                                                          expectSuccess:NO
                                                                   line:__LINE__];
    XCTAssertTrue([result.error.errorDetails rangeOfString:@"certificate"].location != NSNotFound);
    
    //Unreachable authority:
    instance.authority = @"https://SomeReallyNonExistingDomain.com/SomeTenant";
    instance.validateAuthority = NO;
    [self callAcquireTokenWithInstance:instance
                       refresh_session:NO
                           interactive:NO
                          keepSignedIn:YES
                         expectSuccess:NO
                                  line:__LINE__];
    
    //Cannot be validated:
    instance.authority = @"https://microsoft.com/SomeTenant";
    instance.validateAuthority = YES;
    result = [self callAcquireTokenWithInstance:instance
                                refresh_session:NO
                                    interactive:NO
                                   keepSignedIn:YES
                                  expectSuccess:NO
                                           line:__LINE__];
    XCTAssertEqual((long)result.error.code, (long)AD_ERROR_AUTHORITY_VALIDATION);
}

-(long) cacheCount
{
    id<ADTokenCacheEnumerator> cache = [ADAuthenticationSettings sharedInstance].defaultTokenCacheStore;
    ADAuthenticationError* error = nil;
    NSArray* all = [cache allItemsWithError:&error];
    XCTAssertNotNil(all);
    XCTAssertNil(error.errorDetails);
    return all.count;
}

//Verifies that error is generated in case of wrong user authentication
-(void) testWrongUser
{
    //Clean, request one user, enter another
    XCTAssertEqual([self cacheCount], (long)0);//Access token and MRRT
    ADAuthenticationResult* result = [self callAcquireTokenWithInstance:[self getAADInstance]
                                                        refresh_session:NO
                                                            interactive:YES
                                                           keepSignedIn:YES
                                                          expectSuccess:NO
                                                                 userId:@"Nonexistent"
                                                                   line:__LINE__];
    XCTAssertNil(result.tokenCacheItem);
    XCTAssertEqual([self cacheCount], (long)2);//Access token and MRRT
    //Cache present, same:
    result = [self callAcquireTokenWithInstance:[self getAADInstance]
                                refresh_session:NO
                                    interactive:NO
                                   keepSignedIn:NO
                                  expectSuccess:NO
                                         userId:@"Nonexistent"
                                           line:__LINE__];
    XCTAssertNil(result.tokenCacheItem);
    XCTAssertEqual((long)result.error.code, (long)AD_ERROR_WRONG_USER);
    XCTAssertEqual([self cacheCount], (long)2);//Access token and MRRT
}

-(void) testRefreshSession
{
    ADTestInstance* instance = [self getAADInstance];
    //Start with getting a normal token that will be refreshed later:
    ADAuthenticationResult* result1 = [self callAcquireTokenWithInstance:instance
                                                         refresh_session:NO
                                                             interactive:YES
                                                            keepSignedIn:YES
                                                           expectSuccess:YES
                                                                    line:__LINE__];

    //This one will use the cookies, but should re-authorize with the refres_session parameter:
    ADAuthenticationResult* result2 = [self callAcquireTokenWithInstance:instance
                                                         refresh_session:YES
                                                             interactive:NO
                                                            keepSignedIn:YES
                                                           expectSuccess:YES
                                                                    line:__LINE__];
    XCTAssertNotEqualObjects(result1.accessToken, result2.accessToken);
    
    //Retry without the cache, cookies should still be used:
    [self clearCache];
    [self callAcquireTokenWithInstance:instance
                       refresh_session:YES
                           interactive:NO
                          keepSignedIn:YES
                         expectSuccess:YES
                                  line:__LINE__];
    
    //Now clear both cache and cookies, normal interactive session should be invoked:
    [self clearCache];
    [self clearCookies];
    [self callAcquireTokenWithInstance:instance
                       refresh_session:YES
                           interactive:YES
                          keepSignedIn:YES
                         expectSuccess:YES
                                  line:__LINE__];}

@end
