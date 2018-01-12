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

#import "ADALBaseTest.h"

@interface PingInteractiveLoginTests : ADALBaseTest

@end

@implementation PingInteractiveLoginTests

#pragma mark - Setup

- (void)setUp
{
    [super setUp];
    [self launchTestAppWithDefaultTab];
    [self clearCache];
    [self clearCookies];
}

#pragma mark - WebView

- (void)signinToPingWithUsername:(NSString *)username password:(NSString *)password
{
    // Wait for Ping page to load
    XCUIElement *usernameField = [_testApplication.textFields elementBoundByIndex:0];
    NSPredicate *predicate = [NSPredicate predicateWithFormat:@"exists == 1"];
    
    [self expectationForPredicate:predicate evaluatedWithObject:usernameField handler:nil];
    [self waitForExpectationsWithTimeout:20.0f handler:nil];
    
    // Enter the username
    [usernameField pressForDuration:0.5f];
    [usernameField typeText:username];
    
    XCUIElement *passwordField = [_testApplication.secureTextFields elementBoundByIndex:0];
    [passwordField pressForDuration:0.5f];
    [passwordField typeText:password];
    
    // Tap sign in
    XCUIElementQuery *buttons = [_testApplication.staticTexts matchingIdentifier:@"Sign On"];
    
    // Because ping login page has two "Sign On" labels of the same type, tap both
    [[buttons elementBoundByIndex:0] tap];
    
    if (buttons.count > 1)
    {
        [[buttons elementBoundByIndex:1] tap];
    }
}

#pragma mark - Tests

// #290995 iteration 9
- (void)testInteractivePingLogin_withPromptAlways_noLoginHint_ADALWebView
{
    // Setup configuration
    [self selectProfile:@"OneDrive"];
    [self enterUserId:@""];
    [self selectUserIdType:@"Optional"];
    [self selectPromptBehavior:@"Always"];
    [self selectWebViewType:@"ADAL"];
    
    // Start interactive auth
    [self acquireToken];
    [self enterAADUsername:DEFAULT_PING_USERNAME];
    
    // Wait for AAD redirrect text
    [self waitForAADRedirrect];
    
    // Sign in to Ping page
    [self signinToPingWithUsername:DEFAULT_PING_USERID password:DEFAULT_PING_PASSWORD];
    
    // Wait for result
    [self waitForTokenResultWithCompletionHandler:^(NSDictionary *result) {
        
        XCTAssertEqualObjects(result[@"status"], @"AD_SUCCEEDED");
        XCTAssertTrue([result[@"token_access_token"] length] > 0);
        XCTAssertEqual([result[@"error"] length], 0);
        
    }];
    
    // Tap the "acquire" button again, UI should appear
    [self startAndCancelInteractiveSignin];
}

// #290995 iteration 10
- (void)testInteractivePingLogin_withPromptAlways_withLoginHint_ADALWebView
{
    // Setup configuration
    [self selectProfile:@"OneDrive"];
    
    [self enterUserId:DEFAULT_PING_USERNAME];
    [self selectUserIdType:@"Optional"];
    [self selectPromptBehavior:@"Always"];
    [self selectWebViewType:@"ADAL"];
    
    // Start interactive auth
    [self acquireToken];
    
    // Sign in to Ping page
    [self signinToPingWithUsername:DEFAULT_PING_USERID password:DEFAULT_PING_PASSWORD];
    
    // Wait for result
    [self waitForTokenResultWithCompletionHandler:^(NSDictionary *result) {
        
        XCTAssertEqualObjects(result[@"status"], @"AD_SUCCEEDED");
        XCTAssertTrue([result[@"token_access_token"] length] > 0);
        XCTAssertEqual([result[@"error"] length], 0);
        
    }];
    
    // Tap the "acquire" button again, UI should appear
    [self startAndCancelInteractiveSignin];
}


@end
