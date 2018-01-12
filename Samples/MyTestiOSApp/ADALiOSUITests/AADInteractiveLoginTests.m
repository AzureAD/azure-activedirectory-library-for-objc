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

@interface AADInteractiveLoginTests : ADALBaseTest

@end

@implementation AADInteractiveLoginTests

#pragma mark - Setup

- (void)setUp
{
    [super setUp];
    [self launchTestAppWithDefaultTab];
    [self clearCache];
    [self clearCookies];
}

#pragma mark - WebView

- (void)signinToAADWithPassword:(NSString *)password
{
    // Wait for AAD username page to load
    XCUIElement *passwordSecureTextField = _testApplication/*@START_MENU_TOKEN@*/.secureTextFields[@"Password"]/*[[".otherElements[@\"Sign in to your account\"].secureTextFields[@\"Password\"]",".secureTextFields[@\"Password\"]"],[[[-1,1],[-1,0]]],[0]]@END_MENU_TOKEN@*/;
    NSPredicate *predicate = [NSPredicate predicateWithFormat:@"exists == 1"];
    
    [self expectationForPredicate:predicate
              evaluatedWithObject:passwordSecureTextField handler:nil];
    [self waitForExpectationsWithTimeout:20.0f handler:nil];
    
    // Enter the password
    [passwordSecureTextField pressForDuration:0.5f];
    [passwordSecureTextField typeText:password];
    
    // Tap sign in
    XCUIElement *signInButton = _testApplication/*@START_MENU_TOKEN@*/.buttons[@"Sign in"]/*[[".otherElements[@\"Sign in to your account\"].buttons[@\"Sign in\"]",".buttons[@\"Sign in\"]"],[[[-1,1],[-1,0]]],[0]]@END_MENU_TOKEN@*/;
    [signInButton tap];
}

- (void)signinToBlackforestAADWithPassword:(NSString *)password
{
    // Wait for AAD username page to load
    XCUIElement *usernameField = _testApplication.textFields[@"User account"];
    NSPredicate *predicate = [NSPredicate predicateWithFormat:@"exists == 1"];
    
    [self expectationForPredicate:predicate
              evaluatedWithObject:usernameField handler:nil];
    [self waitForExpectationsWithTimeout:20.0f handler:nil];
    
    // Enter the password
    XCUIElement *passwordSecureTextField = _testApplication/*@START_MENU_TOKEN@*/.secureTextFields[@"Password"]/*[[".otherElements[@\"Sign in to your account\"].secureTextFields[@\"Password\"]",".secureTextFields[@\"Password\"]"],[[[-1,1],[-1,0]]],[0]]@END_MENU_TOKEN@*/;
    [passwordSecureTextField pressForDuration:0.5f];
    [usernameField pressForDuration:0.5f];
    // Blackforest signing page does some additional redirrection which happens as soon as you tap any text fields
    [passwordSecureTextField pressForDuration:1.0f];
    [passwordSecureTextField typeText:password];
    
    [_testApplication.buttons[@"Done"] tap];
    
    // Tap sign in
    XCUIElement *signInButton = _testApplication/*@START_MENU_TOKEN@*/.buttons[@"Sign in"]/*[[".otherElements[@\"Sign in to your account\"].buttons[@\"Sign in\"]",".buttons[@\"Sign in\"]"],[[[-1,1],[-1,0]]],[0]]@END_MENU_TOKEN@*/;
    [signInButton tap];
}

#pragma mark - Tests

// #290995 iteration 1
- (void)testInteractiveAADLogin_withPromptAlways_noLoginHint_ADALWebView
{
    // Setup configuration
    [self selectProfile:@"OneDrive"];
    [self enterUserId:@""];
    [self selectUserIdType:@"Optional"];
    [self selectPromptBehavior:@"Always"];
    [self selectWebViewType:@"ADAL"];

    // Start interactive auth
    [self acquireToken];
    [self enterAADUsername:DEFAULT_AAD_USERNAME];
    [self signinToAADWithPassword:DEFAULT_AAD_PASSWORD];
    
    // Wait for result
    [self waitForTokenResultWithCompletionHandler:^(NSDictionary *result) {
        
        XCTAssertEqualObjects(result[@"status"], @"AD_SUCCEEDED");
        XCTAssertTrue([result[@"token_access_token"] length] > 0);
        XCTAssertEqual([result[@"error"] length], 0);
        
    }];
    
    // Tap the "acquire" button again, UI should appear
    [self startAndCancelInteractiveSignin];
    
}

// #290995 iteration 2
- (void)testInteractiveAADLogin_withPromptAlways_withLoginHint_ADALWebView
{
    // Setup configuration
    [self selectProfile:@"OneDrive"];
    [self enterUserId:DEFAULT_AAD_USERNAME];
    [self selectUserIdType:@"Optional"];
    [self selectPromptBehavior:@"Always"];
    [self selectWebViewType:@"ADAL"];
    
    // Start interactive auth
    [self acquireToken];
    [self signinToAADWithPassword:DEFAULT_AAD_PASSWORD];
    
    // Wait for result
    [self waitForTokenResultWithCompletionHandler:^(NSDictionary *result) {
        
        XCTAssertEqualObjects(result[@"status"], @"AD_SUCCEEDED");
        XCTAssertTrue([result[@"token_access_token"] length] > 0);
        XCTAssertEqual([result[@"error"] length], 0);
        
    }];
    
    // Tap the "acquire" button again, UI should appear
    [self startAndCancelInteractiveSignin];
}

// #290995 iteration 3
- (void)testInteractiveAADLogin_withPromptAuto_withLoginHint_ADALWebView
{
    // Setup configuration
    [self selectProfile:@"OneDrive"];
    [self enterUserId:DEFAULT_AAD_USERNAME];
    [self selectUserIdType:@"Optional"];
    [self selectPromptBehavior:@"Auto"];
    [self selectWebViewType:@"ADAL"];
    
    // Start interactive auth
    [self acquireToken];
    [self signinToAADWithPassword:DEFAULT_AAD_PASSWORD];
    
    __block NSString *firstCorrelationId = nil;
    
    // Wait for result
    [self waitForTokenResultWithCompletionHandler:^(NSDictionary *result) {
        
        XCTAssertEqualObjects(result[@"status"], @"AD_SUCCEEDED");
        XCTAssertTrue([result[@"token_access_token"] length] > 0);
        XCTAssertEqual([result[@"error"] length], 0);
        
        firstCorrelationId = result[@"correlation_id"];
        
    }];
    
    // Acquire token again
    [self acquireToken];
    
    // Wait for result immediately, no user action required
    [self waitForTokenResultWithCompletionHandler:^(NSDictionary *result) {
        
        XCTAssertEqualObjects(result[@"status"], @"AD_SUCCEEDED");
        XCTAssertTrue([result[@"token_access_token"] length] > 0);
        XCTAssertEqual([result[@"error"] length], 0);
        
        XCTAssertNotEqualObjects(result[@"correlation_id"], firstCorrelationId);
    }];
}

// #290995 iteration 4
- (void)testInteractiveAADLogin_withPromptAlways_withLoginHint_PassedInWebView
{
    // Setup configuration
    [self selectProfile:@"OneDrive"];
    [self enterUserId:DEFAULT_AAD_USERNAME];
    [self selectUserIdType:@"Optional"];
    [self selectPromptBehavior:@"Always"];
    [self selectWebViewType:@"Passed In"];
    
    // Start interactive auth
    [self acquireToken];
    [self signinToAADWithPassword:DEFAULT_AAD_PASSWORD];
    
    // Wait for result
    [self waitForTokenResultWithCompletionHandler:^(NSDictionary *result) {
        
        XCTAssertEqualObjects(result[@"status"], @"AD_SUCCEEDED");
        XCTAssertTrue([result[@"token_access_token"] length] > 0);
        XCTAssertEqual([result[@"error"] length], 0);
        
    }];
    
    // Tap the "acquire" button again.
    [self acquireToken];
    // UI should appear
    [_testApplication.buttons[@"Cancel"] tap];
}

// #290995 iteration 13
- (void)testInteractiveAADLogin_withBlackforestUser_withPromptAlways_noLoginHint_ADALWebView
{
    // Setup configuration
    [self selectProfile:@"Black Forest Com"];
    [self enterUserId:@""];
    [self selectUserIdType:@"Optional"];
    [self selectPromptBehavior:@"Always"];
    [self selectWebViewType:@"ADAL"];
    [self enterEQP:@"instance_aware=true"];
    
    // Start interactive auth
    [self acquireToken];
    [self enterAADUsername:DEFAULT_BLACKFOREST_USERNAME];
    [self signinToBlackforestAADWithPassword:DEFAULT_BLACKFOREST_PASSWORD];
    
    // Wait for result
    [self waitForTokenResultWithCompletionHandler:^(NSDictionary *result) {
        
        XCTAssertEqualObjects(result[@"status"], @"AD_SUCCEEDED");
        XCTAssertTrue([result[@"token_access_token"] length] > 0);
        XCTAssertEqual([result[@"error"] length], 0);
        XCTAssertEqualObjects(result[@"authority"], @"https://login.microsoftonline.de/common");
        XCTAssertEqualObjects(result[@"token_authority"], @"https://login.microsoftonline.de/common");
        
    }];
    
    // Tap the "acquire" button again, UI should appear
    [self startAndCancelInteractiveSignin];
}

// #290995 iteration 14
- (void)testInteractiveAADLogin_withBlackforestUser_withPromptAlways_withLoginHint_ADALWebView
{
    // Setup configuration
    [self selectProfile:@"Black Forest Com"];
    [self enterUserId:DEFAULT_BLACKFOREST_USERNAME];
    [self selectUserIdType:@"Optional"];
    [self selectPromptBehavior:@"Always"];
    [self selectWebViewType:@"ADAL"];
    [self enterEQP:@"instance_aware=true"];
    
    // Start interactive auth
    [self acquireToken];
    [self waitForAADLoginPage];
    
    // Press next (this is special AAD behavior in case of sovereign clouds)
    XCUIElement *nextButton = _testApplication.buttons[@"Next"];
    [nextButton tap];
    
    [self signinToBlackforestAADWithPassword:DEFAULT_BLACKFOREST_PASSWORD];
    
    // Wait for result
    [self waitForTokenResultWithCompletionHandler:^(NSDictionary *result) {
        
        XCTAssertEqualObjects(result[@"status"], @"AD_SUCCEEDED");
        XCTAssertTrue([result[@"token_access_token"] length] > 0);
        XCTAssertEqual([result[@"error"] length], 0);
        XCTAssertEqualObjects(result[@"authority"], @"https://login.microsoftonline.de/common");
        XCTAssertEqualObjects(result[@"token_authority"], @"https://login.microsoftonline.de/common");
        
    }];
    
    // Tap the "acquire" button again, UI should appear
    [self startAndCancelInteractiveSignin];
    
}

@end
