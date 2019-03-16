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
#import "MSIDTestConfigurationProvider.h"
#import "XCUIElement+ADALiOSUITests.h"
#import "MSIDTestAutomationConfiguration.h"
#import "MSIDAutomationConfigurationRequest.h"

@class MSIDAutomationErrorResult;
@class MSIDAutomationSuccessResult;

@interface ADALBaseUITest : XCTestCase

@property (nonatomic) XCUIApplication *testApp;
@property (nonatomic, class) MSIDTestConfigurationProvider *confProvider;
@property (nonatomic) MSIDTestAccount *primaryAccount;
@property (nonatomic) MSIDTestAutomationConfiguration *testConfiguration;

// Result
- (MSIDAutomationErrorResult *)automationErrorResult;
- (MSIDAutomationSuccessResult *)automationSuccessResult;
- (NSDictionary *)automationResultDictionary;
- (NSDictionary *)resultIDTokenClaims;

// Asserts
- (void)assertRefreshTokenInvalidated;
- (void)assertAccessTokenExpired;
- (void)assertAuthUIAppear;
- (void)assertErrorCode:(NSString *)expectedErrorCode;
- (void)assertErrorDescription:(NSString *)errorDescription;
- (void)assertErrorSubcode:(NSString *)errorSubcode;
- (void)assertAccessTokenNotNil;
- (void)assertRefreshTokenNotNil;

// Actions
- (void)performAction:(NSString *)action withConfig:(NSDictionary *)config;
- (void)aadEnterEmail;
- (void)aadEnterEmail:(NSString *)email app:(XCUIApplication *)app;
- (void)aadEnterPassword;
- (void)enterPassword:(NSString *)password app:(XCUIApplication *)app;
- (void)closeResultView;
- (void)invalidateRefreshToken:(NSDictionary *)config;
- (void)expireAccessToken:(NSDictionary *)config;
- (void)acquireToken:(NSDictionary *)config;
- (void)acquireTokenSilent:(NSDictionary *)config;
- (void)clearKeychain;
- (void)clearCookies;
- (void)openURL:(NSDictionary *)config;
- (void)blackForestWaitForNextButton:(XCUIApplication *)application;
- (void)closeAuthUI;
- (void)acquireTokenWithRefreshToken:(NSDictionary *)config;

// Helpers
- (void)waitForElement:(id)object;
- (void)loadTestConfiguration:(MSIDAutomationConfigurationRequest *)request;
- (void)loadPasswordForAccount:(MSIDTestAccount *)account;
- (NSDictionary *)configWithTestRequest:(MSIDAutomationTestRequest *)request;

// Shared steps
- (void)runSharedAuthUIAppearsStepWithTestRequest:(MSIDAutomationTestRequest *)request;
- (NSString *)runSharedResultAssertionWithTestRequest:(MSIDAutomationTestRequest *)request;
- (void)runSharedSilentLoginWithTestRequest:(MSIDAutomationTestRequest *)request;
- (NSString *)runSharedAADLoginWithTestRequest:(MSIDAutomationTestRequest *)request;

@end
